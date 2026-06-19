package org.matrix.TEESimulator.interception.keystore

import android.annotation.SuppressLint
import android.os.IBinder
import android.os.Parcel
import android.security.Credentials
import android.security.KeyStore
import android.security.keymaster.ExportResult
import android.security.keymaster.KeyCharacteristics
import android.security.keymaster.KeymasterArguments
import android.security.keymaster.KeymasterCertificateChain
import android.security.keymaster.KeymasterDefs
import android.security.keystore.IKeystoreCertificateChainCallback
import android.security.keystore.IKeystoreExportKeyCallback
import android.security.keystore.IKeystoreKeyCharacteristicsCallback
import android.security.keystore.IKeystoreService
import java.math.BigInteger
import java.security.KeyPair
import java.security.cert.Certificate
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils.extractAlias
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper

@SuppressLint("BlockedPrivateApi", "PrivateApi")
object KeystoreInterceptor : AbstractKeystoreInterceptor() {

    private val GET_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "get")
    }
    private val GENERATE_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "generateKey")
    }
    private val GET_KEY_CHARACTERISTICS_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "getKeyCharacteristics")
    }
    private val EXPORT_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "exportKey")
    }
    private val ATTEST_KEY_TRANSACTION by lazy {
        InterceptorUtils.getTransactCode(IKeystoreService.Stub::class.java, "attestKey")
    }

    private val transactionNames: Map<Int, String> by lazy {
        IKeystoreService.Stub::class.java.declaredFields
            .filter { it.isAccessible = true; it.type == Int::class.java && it.name.startsWith("TRANSACTION_") }
            .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
    }

    private val generateKeyHandlers: Map<Int, (Long, Int, Int, Parcel) -> TransactionResult> by lazy {
        mapOf(
            GENERATE_KEY_TRANSACTION to ::handleGenerateKey,
            GET_KEY_CHARACTERISTICS_TRANSACTION to ::handleGetKeyCharacteristics,
            EXPORT_KEY_TRANSACTION to ::handleExportKey,
            ATTEST_KEY_TRANSACTION to ::handleAttestKey,
        )
    }

    override val serviceName = "android.security.keystore"
    override val processName = "keystore"
    override val injectionCommand = "exec ./inject `pidof keystore` libTEESimulator.so entry"

    private val keygenParameters = ConcurrentHashMap<KeyIdentifier, LegacyKeygenParameters>()
    private val generatedKeyPairs = ConcurrentHashMap<KeyIdentifier, KeyPair>()
    private val patchedChainCache = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()

    override fun onPreTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
    ): TransactionResult {
        if (ConfigurationManager.shouldGenerate(callingUid)) {
            generateKeyHandlers[code]?.let { handler ->
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)
                return handler(txId, callingUid, callingPid, data)
            }
        }
        if (ConfigurationManager.shouldPatch(callingUid) && code == GET_TRANSACTION) {
            logTransaction(txId, transactionNames[code]!!, callingUid, callingPid, true)
            return TransactionResult.Continue
        }
        logTransaction(txId, transactionNames[code] ?: "unknown code=$code", callingUid, callingPid, true)
        return TransactionResult.ContinueAndSkipPost
    }

    private fun handleGenerateKey(txId: Long, uid: Int, pid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val callback = IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder())
                val alias = extractAlias(data.readString()!!)
                val keyId = KeyIdentifier(uid, alias)
                val keymasterArgs = KeymasterArguments()
                if (data.readInt() == 1) keymasterArgs.readFromParcel(data)
                keygenParameters[keyId] = LegacyKeygenParameters.fromKeymasterArguments(keymasterArgs)
                val characteristics = KeyCharacteristics().apply {
                    swEnforced = KeymasterArguments(); hwEnforced = keymasterArgs
                }
                callback.onFinished(InterceptorUtils.createSuccessKeystoreResponse(), characteristics)
                InterceptorUtils.createSuccessReply()
            }.getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed during handleGenerateKey.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun handleGetKeyCharacteristics(txId: Long, uid: Int, pid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val callback = IKeystoreKeyCharacteristicsCallback.Stub.asInterface(data.readStrongBinder())
                val alias = extractAlias(data.readString()!!)
                val keyId = KeyIdentifier(uid, alias)
                val params = keygenParameters[keyId] ?: throw IllegalStateException("No params found for $keyId")
                val characteristics = KeyCharacteristics().apply {
                    swEnforced = KeymasterArguments()
                    hwEnforced = KeymasterArguments().apply { addEnum(KeymasterDefs.KM_TAG_ALGORITHM, params.algorithm) }
                }
                callback.onFinished(InterceptorUtils.createSuccessKeystoreResponse(), characteristics)
                InterceptorUtils.createSuccessReply()
            }.getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed during handleGetKeyCharacteristics.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun handleExportKey(txId: Long, uid: Int, pid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val callback = IKeystoreExportKeyCallback.Stub.asInterface(data.readStrongBinder())
                val alias = extractAlias(data.readString()!!)
                val keyId = KeyIdentifier(uid, alias)
                val params = keygenParameters[keyId] ?: throw IllegalStateException("No params found for $keyId")
                val keyPair = CertificateGenerator.generateSoftwareKeyPair(params.toKeyMintAttestation())
                    ?: throw Exception("Failed to generate software key pair.")
                generatedKeyPairs[keyId] = keyPair
                val exportResultParcel = Parcel.obtain().apply {
                    writeInt(KeyStore.NO_ERROR); writeByteArray(keyPair.public.encoded); setDataPosition(0)
                }
                val exportResult = ExportResult.CREATOR.createFromParcel(exportResultParcel)
                exportResultParcel.recycle()
                callback.onFinished(exportResult)
                InterceptorUtils.createSuccessReply()
            }.getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed during handleExportKey.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    private fun handleAttestKey(txId: Long, uid: Int, pid: Int, data: Parcel): TransactionResult {
        return runCatching {
                data.enforceInterface(IKeystoreService.DESCRIPTOR)
                val callback = IKeystoreCertificateChainCallback.Stub.asInterface(data.readStrongBinder())
                val alias = extractAlias(data.readString()!!)
                val keyId = KeyIdentifier(uid, alias)
                val params = keygenParameters[keyId] ?: throw IllegalStateException("No params found for $keyId")
                val keyPair = generatedKeyPairs[keyId] ?: throw IllegalStateException("No keypair found for $keyId")
                val attestationArgs = KeymasterArguments()
                if (data.readInt() == 1) {
                    attestationArgs.readFromParcel(data)
                    val challenge = attestationArgs.getBytes(KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE, ByteArray(0))
                    params.attestationChallenge = challenge
                }
                val certificateChain = CertificateGenerator.generateCertificateChain(
                    uid, keyPair, null, params.toKeyMintAttestation(), 1,
                ) ?: throw Exception("CertificateGenerator failed to create attested key pair.")
                val chainAsByteList = certificateChain.map { it.encoded }
                val certChain = KeymasterCertificateChain(chainAsByteList)
                callback.onFinished(InterceptorUtils.createSuccessKeystoreResponse(), certChain)
                InterceptorUtils.createSuccessReply()
            }.getOrElse {
                SystemLogger.error("[TX_ID: $txId] Failed during handleAttestKey.", it)
                TransactionResult.ContinueAndSkipPost
            }
    }

    override fun onPostTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
        reply: Parcel?, resultCode: Int,
    ): TransactionResult {
        if (target != keystoreService || code != GET_TRANSACTION || reply == null || InterceptorUtils.hasException(reply)) {
            return TransactionResult.SkipTransaction
        }
        if (!ConfigurationManager.shouldPatch(callingUid)) return TransactionResult.SkipTransaction
        return try {
            data.enforceInterface(IKeystoreService.DESCRIPTOR)
            val alias = data.readString() ?: ""
            val extractedAlias = extractAlias(alias)
            val keyId = KeyIdentifier(callingUid, extractedAlias)
            when {
                alias.startsWith(Credentials.USER_CERTIFICATE) -> {
                    logTransaction(txId, "post-get (user cert)", callingUid, callingPid)
                    val originalLeafBytes = reply.createByteArray() ?: return TransactionResult.SkipTransaction
                    val originalLeafCertResult = CertificateHelper.toCertificate(originalLeafBytes)
                    if (originalLeafCertResult !is CertificateHelper.OperationResult.Success) return TransactionResult.SkipTransaction
                    val originalLeafCert = originalLeafCertResult.data
                    val tempChain = arrayOf<Certificate>(originalLeafCert)
                    val newFullChain = AttestationPatcher.patchCertificateChain(tempChain, callingUid)
                    if (newFullChain.isNotEmpty() && newFullChain[0] != originalLeafCert) {
                        patchedChainCache[keyId] = newFullChain
                        SystemLogger.info("[TX_ID: $txId] Patched and cached chain for alias '$extractedAlias'. Returning new leaf.")
                        InterceptorUtils.createByteArrayReply(newFullChain[0].encoded)
                    } else TransactionResult.SkipTransaction
                }
                alias.startsWith(Credentials.CA_CERTIFICATE) -> {
                    logTransaction(txId, "post-get (ca cert)", callingUid, callingPid)
                    val cachedChain = patchedChainCache.remove(keyId)
                    if (cachedChain != null && cachedChain.size > 1) {
                        val caCerts = cachedChain.drop(1)
                        val caCertsBytes = CertificateHelper.certificatesToByteArray(caCerts)
                        SystemLogger.info("[TX_ID: $txId] Returning cached CA chain for alias '$extractedAlias'.")
                        InterceptorUtils.createByteArrayReply(caCertsBytes!!)
                    } else {
                        SystemLogger.warning("[TX_ID: $txId] No cached chain found for CA request on alias '$extractedAlias'. Skipping.")
                        TransactionResult.SkipTransaction
                    }
                }
                else -> TransactionResult.SkipTransaction
            }
        } catch (e: Exception) {
            SystemLogger.error("[TX_ID: $txId] Failed during legacy post-transaction patching.", e)
            TransactionResult.SkipTransaction
        }
    }
}

private data class LegacyKeygenParameters(
    val algorithm: Int,
    val keySize: Int,
    val purpose: List<Int>,
    val digest: List<Int>,
    val certificateNotBefore: Date?,
    val rsaPublicExponent: BigInteger?,
    val ecCurveName: String?,
) {
    var attestationChallenge: ByteArray? = null

    fun toKeyMintAttestation(): KeyMintAttestation = KeyMintAttestation(
        keySize = this.keySize, algorithm = this.algorithm,
        ecCurve = 0, ecCurveName = this.ecCurveName ?: "", origin = null,
        blockMode = listOf(), padding = listOf(),
        purpose = this.purpose, digest = this.digest,
        rsaPublicExponent = this.rsaPublicExponent,
        certificateSerial = null, certificateSubject = null,
        certificateNotBefore = this.certificateNotBefore, certificateNotAfter = null,
        attestationChallenge = this.attestationChallenge,
        brand = null, device = null, product = null, serial = null,
        imei = null, meid = null, manufacturer = null, model = null, secondImei = null,
        activeDateTime = null, originationExpireDateTime = null, usageExpireDateTime = null,
        usageCountLimit = null, callerNonce = null, nonce = null,
        unlockedDeviceRequired = null, includeUniqueId = null,
        rollbackResistance = null, earlyBootOnly = null, allowWhileOnBody = null,
        trustedUserPresenceRequired = null, trustedConfirmationRequired = null,
        noAuthRequired = null, maxUsesPerBoot = null, maxBootLevel = null,
        minMacLength = null, rsaOaepMgfDigest = emptyList(),
    )

    companion object {
        fun fromKeymasterArguments(args: KeymasterArguments): LegacyKeygenParameters {
            val algorithm = args.getEnum(KeymasterDefs.KM_TAG_ALGORITHM, 0)
            val keySize = args.getUnsignedInt(KeymasterDefs.KM_TAG_KEY_SIZE, 0).toInt()
            return LegacyKeygenParameters(
                algorithm = algorithm, keySize = keySize,
                purpose = args.getEnums(KeymasterDefs.KM_TAG_PURPOSE),
                digest = args.getEnums(KeymasterDefs.KM_TAG_DIGEST),
                certificateNotBefore = args.getDate(KeymasterDefs.KM_TAG_ACTIVE_DATETIME, Date()),
                rsaPublicExponent = if (algorithm == KeymasterDefs.KM_ALGORITHM_RSA) getRsaExponent(args) else null,
                ecCurveName = if (algorithm == KeymasterDefs.KM_ALGORITHM_EC) deriveEcCurveName(keySize) else null,
            )
        }

        private fun deriveEcCurveName(keySize: Int): String = when (keySize) {
            224 -> "secp224r1"; 256 -> "secp256r1"; 384 -> "secp384r1"; 521 -> "secp521r1"
            else -> "secp256r1"
        }

        private fun getRsaExponent(args: KeymasterArguments): BigInteger? {
            return runCatching {
                val getArgumentByTag = KeymasterArguments::class.java.getDeclaredMethod("getArgumentByTag", Int::class.java)
                getArgumentByTag.isAccessible = true
                val rsaArgument = getArgumentByTag.invoke(args, KeymasterDefs.KM_TAG_RSA_PUBLIC_EXPONENT)
                val getLongTagValue = KeymasterArguments::class.java.getDeclaredMethod(
                    "getLongTagValue", Class.forName("android.security.keymaster.KeymasterArgument"))
                getLongTagValue.isAccessible = true
                getLongTagValue.invoke(args, rsaArgument) as BigInteger
            }.onFailure { SystemLogger.error("Failed to read rsaPublicExponent via reflection.", it) }.getOrNull()
        }
    }
}
