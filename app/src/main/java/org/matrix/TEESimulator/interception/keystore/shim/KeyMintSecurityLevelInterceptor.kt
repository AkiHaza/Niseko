package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.EcCurve
import android.hardware.security.keymint.KeyParameter
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.KeyParameterValue
import android.hardware.security.keymint.KeyOrigin
import android.hardware.security.keymint.SecurityLevel
import android.hardware.security.keymint.Tag
import android.os.IBinder
import android.os.Parcel
import android.system.keystore2.*
import android.util.Pair as AndroidPair
import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.KeyPair
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Date
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.LockSupport
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.attestation.AttestationPatcher
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.interception.keystore.InterceptorUtils
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.interception.keystore.Keystore2Interceptor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateGenerator
import org.matrix.TEESimulator.pki.CertificateHelper
import org.matrix.TEESimulator.pki.KeyBoxManager
import org.matrix.TEESimulator.util.AndroidDeviceUtils
import org.matrix.TEESimulator.util.AndroidPermissionUtils
import org.matrix.TEESimulator.util.TeeLatencySimulator

class KeyMintSecurityLevelInterceptor(
    private val original: IKeystoreSecurityLevel,
    private val securityLevel: Int,
) : BinderInterceptor() {

    data class GeneratedKeyInfo(
        val keyPair: KeyPair?,
        val secretKey: javax.crypto.SecretKey?,
        val nspace: Long,
        val response: KeyEntryResponse,
        val keyParams: KeyMintAttestation? = null,
    )

    private val activeOps = ConcurrentHashMap<Int, ConcurrentLinkedDeque<SoftwareOperation>>()
    private val recentOps = ConcurrentHashMap<Int, ConcurrentLinkedDeque<Long>>()

    override fun onPreTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
    ): TransactionResult {
        when (code) {
            GENERATE_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)
                return handleGenerateKey(txId, callingUid, callingPid, data)
            }
            CREATE_OPERATION_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)
                return handleCreateOperation(txId, callingUid, data)
            }
            IMPORT_KEY_TRANSACTION -> {
                logTransaction(txId, transactionNames[code]!!, callingUid, callingPid)
                data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
                val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                    ?: return TransactionResult.ContinueAndSkipPost
                SystemLogger.info("[TX_ID: $txId] Forward to post-importKey hook for ${keyDescriptor.alias}[${keyDescriptor.nspace}]")
                return TransactionResult.Continue
            }
        }
        logTransaction(txId, transactionNames[code] ?: "unknown code=$code", callingUid, callingPid, true)
        return TransactionResult.ContinueAndSkipPost
    }

    override fun onPostTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel, reply: Parcel?, resultCode: Int,
    ): TransactionResult {
        if (resultCode != 0 || reply == null || InterceptorUtils.hasException(reply))
            return TransactionResult.SkipTransaction

        if (code == IMPORT_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return TransactionResult.SkipTransaction
            val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
            if (generatedKeys.remove(keyId) != null) {
                SystemLogger.debug("Remove generated key on importKey $keyId")
                GeneratedKeyPersistence.delete(keyId)
            }
            teeResponses.remove(keyId)
            patchedChains.remove(keyId)
            attestationKeys.remove(keyId)
            importedKeys.add(keyId)
            if (!ConfigurationManager.shouldSkipUid(callingUid)) {
                val metadata: KeyMetadata = reply.readTypedObject(KeyMetadata.CREATOR)
                    ?: return TransactionResult.SkipTransaction
                val originalChain = CertificateHelper.getCertificateChain(metadata)
                if (originalChain != null && originalChain.size > 1) {
                    val newChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid)
                    CertificateHelper.updateCertificateChain(metadata, newChain).getOrThrow()
                    metadata.authorizations = InterceptorUtils.patchAuthorizations(metadata.authorizations, callingUid)
                    patchedChains[keyId] = newChain
                    teeResponses[keyId] = KeyEntryResponse().apply {
                        this.metadata = metadata
                        iSecurityLevel = original
                    }
                    SystemLogger.debug("Cached patched certificate chain for imported key $keyId.")
                    return InterceptorUtils.createTypedObjectReply(metadata)
                }
            }
        } else if (code == CREATE_OPERATION_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return TransactionResult.SkipTransaction
            val params = data.createTypedArray(KeyParameter.CREATOR)
                ?: return TransactionResult.SkipTransaction
            val parsedParams = KeyMintAttestation(params)
            val forced = data.readBoolean()
            if (forced) SystemLogger.verbose { "[TX_ID: $txId] Current operation has a very high pruning power." }
            val response: CreateOperationResponse = reply.readTypedObject(CreateOperationResponse.CREATOR)
                ?: return TransactionResult.SkipTransaction
            response.iOperation?.let { operation ->
                val operationBinder = operation.asBinder()
                if (!interceptedOperations.containsKey(operationBinder)) {
                    SystemLogger.info("Found new IKeystoreOperation. Registering interceptor...")
                    val backdoor = getBackdoor(target)
                    if (backdoor != null) {
                        val isAead = parsedParams.blockMode.firstOrNull() == BlockMode.GCM
                        val interceptor = OperationInterceptor(operation, backdoor, isAead)
                        register(backdoor, operationBinder, interceptor, OperationInterceptor.INTERCEPTED_CODES)
                        interceptedOperations[operationBinder] = interceptor
                    } else {
                        SystemLogger.error("Failed to get backdoor to register OperationInterceptor.")
                    }
                }
            }
        } else if (code == GENERATE_KEY_TRANSACTION) {
            logTransaction(txId, "post-${transactionNames[code]!!}", callingUid, callingPid)
            val metadata: KeyMetadata = reply.readTypedObject(KeyMetadata.CREATOR)
                ?: return TransactionResult.SkipTransaction
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)
                ?: return TransactionResult.SkipTransaction
            val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
            val originalChain = CertificateHelper.getCertificateChain(metadata)
            if (originalChain == null || originalChain.size <= 1) {
                cleanupKeyData(keyId)
                teeResponses[keyId] = KeyEntryResponse().apply {
                    this.metadata = metadata
                    iSecurityLevel = original
                }
                return TransactionResult.SkipTransaction
            }
            data.readTypedObject(KeyDescriptor.CREATOR)
            val keyParams = data.createTypedArray(KeyParameter.CREATOR)
            val certNotBefore = keyParams?.find { it.tag == Tag.CERTIFICATE_NOT_BEFORE }?.value?.dateTime?.let { Date(it) }
            val certNotAfter = keyParams?.find { it.tag == Tag.CERTIFICATE_NOT_AFTER }?.value?.dateTime?.let { Date(it) }
            val newChain = AttestationPatcher.patchCertificateChain(originalChain, callingUid, certNotBefore, certNotAfter)
            val key = metadata.key ?: return TransactionResult.SkipTransaction
            CertificateHelper.updateCertificateChain(metadata, newChain).getOrThrow()
            metadata.authorizations = InterceptorUtils.patchAuthorizations(metadata.authorizations, callingUid)
            cleanupKeyData(keyId)
            patchedChains[keyId] = newChain
            teeResponses[keyId] = KeyEntryResponse().apply {
                this.metadata = metadata
                iSecurityLevel = original
            }
            SystemLogger.debug("Cached patched certificate chain for $keyId. (${key.alias} [${key.domain}, ${key.nspace}])")
            return InterceptorUtils.createTypedObjectReply(metadata)
        }
        return TransactionResult.SkipTransaction
    }

    private fun pruneOpsForUid(uid: Int, newOp: SoftwareOperation, maxOps: Int = MAX_CONCURRENT_OPS_PER_UID) {
        val ops = activeOps.computeIfAbsent(uid) { ConcurrentLinkedDeque() }
        ops.removeIf { it.finalized }
        while (ops.size >= maxOps) {
            val oldest = ops.pollFirst() ?: break
            if (!oldest.finalized) {
                SystemLogger.info("[LRU] Pruning operation for uid=$uid (active=${ops.size}/$maxOps)")
                oldest.abort()
            }
        }
        ops.addLast(newOp)
    }

    private fun trackAndEnforceOpLimit(callingUid: Int, txId: Long): TransactionResult? {
        if (securityLevel != SecurityLevel.STRONGBOX) return null
        val timestamps = recentOps.computeIfAbsent(callingUid) { ConcurrentLinkedDeque() }
        val cutoff = System.nanoTime() - STRONGBOX_OP_WINDOW_NS
        timestamps.removeIf { it < cutoff }
        val swOps = activeOps[callingUid]?.count { !it.finalized } ?: 0
        if (timestamps.size + swOps >= STRONGBOX_MAX_CONCURRENT_OPS) {
            SystemLogger.info("[TX_ID: $txId] StrongBox op limit reached for uid=$callingUid")
            return InterceptorUtils.createErrorReply(KEYMINT_TOO_MANY_OPERATIONS)
        }
        timestamps.addLast(System.nanoTime())
        return null
    }

    private fun handleCreateOperation(txId: Long, callingUid: Int, data: Parcel): TransactionResult = runCatching {
        data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
        val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
        val resolvedEntry: Map.Entry<KeyIdentifier, GeneratedKeyInfo> =
            when (keyDescriptor.domain) {
                Domain.APP -> {
                    val alias = keyDescriptor.alias ?: return TransactionResult.ContinueAndSkipPost
                    val key = KeyIdentifier(callingUid, alias)
                    generatedKeys[key]?.let { java.util.AbstractMap.SimpleEntry(key, it) } ?: return TransactionResult.ContinueAndSkipPost
                }
                Domain.KEY_ID -> {
                    val nspace = keyDescriptor.nspace
                    val entry = if (nspace == null || nspace == 0L) null
                    else generatedKeys.entries.filter { it.key.uid == callingUid }.find { it.value.nspace == nspace }
                    entry ?: run {
                        trackAndEnforceOpLimit(callingUid, txId)?.let { return it }
                        SystemLogger.info("[TX_ID: $txId] createOperation KeyId(${keyDescriptor.nspace}) NOT FOUND for uid=$callingUid. Forwarding to HAL.")
                        return TransactionResult.ContinueAndSkipPost
                    }
                }
                else -> return TransactionResult.ContinueAndSkipPost
            }
        val generatedKeyInfo = resolvedEntry.value
        val resolvedKeyId = resolvedEntry.key
        trackAndEnforceOpLimit(callingUid, txId)?.let { return it }
        SystemLogger.info("[TX_ID: $txId] Creating SOFTWARE operation for uid=$callingUid.")
        val params = data.createTypedArray(KeyParameter.CREATOR)!!
        val parsedParams = KeyMintAttestation(params).let { p ->
            if (p.algorithm != 0) p
            else {
                val keyAlgo = generatedKeyInfo.keyPair?.private?.algorithm
                p.copy(algorithm = when (keyAlgo) {
                    "EC", "ECDSA" -> Algorithm.EC
                    "RSA" -> Algorithm.RSA
                    else -> generatedKeyInfo.keyParams?.algorithm ?: p.algorithm
                })
            }
        }
        val forced = data.readBoolean()
        val requestedPurpose = parsedParams.purpose.firstOrNull()
            ?: return InterceptorUtils.createServiceSpecificErrorReply(KEYMINT_INVALID_ARGUMENT)
        if (forced) return InterceptorUtils.createServiceSpecificErrorReply(RESPONSE_PERMISSION_DENIED)
        AuthorizeCreate.check(generatedKeyInfo.keyParams, parsedParams, params)?.let { errorCode ->
            SystemLogger.info("[TX_ID: $txId] authorize_create rejected: errorCode=$errorCode")
            return InterceptorUtils.createServiceSpecificErrorReply(errorCode)
        }
        val keyParams = generatedKeyInfo.keyParams
        val effectiveParams = if (keyParams != null) {
            keyParams.copy(
                purpose = parsedParams.purpose,
                digest = parsedParams.digest.ifEmpty { keyParams.digest },
                blockMode = parsedParams.blockMode.ifEmpty { keyParams.blockMode },
                padding = parsedParams.padding.ifEmpty { keyParams.padding },
                nonce = parsedParams.nonce,
                minMacLength = parsedParams.minMacLength ?: keyParams.minMacLength,
            )
        } else parsedParams
        val opLatency = when (securityLevel) {
            SecurityLevel.STRONGBOX -> STRONGBOX_OP_LATENCY_FLOOR_MS
            SecurityLevel.TRUSTED_ENVIRONMENT -> TEE_OP_LATENCY_FLOOR_MS
            else -> 0L
        }
        val softwareOperation = SoftwareOperation(txId, generatedKeyInfo.keyPair, generatedKeyInfo.secretKey, effectiveParams, opLatency)
        if (keyParams?.usageCountLimit != null) {
            val limit = keyParams.usageCountLimit
            val remaining = usageCounters.getOrPut(resolvedKeyId) { AtomicInteger(limit) }
            if (remaining.get() <= 0) {
                cleanupKeyData(resolvedKeyId)
                usageCounters.remove(resolvedKeyId)
                return InterceptorUtils.createServiceSpecificErrorReply(RESPONSE_KEY_NOT_FOUND)
            }
            softwareOperation.onFinishCallback = {
                if (remaining.decrementAndGet() <= 0) {
                    cleanupKeyData(resolvedKeyId)
                    usageCounters.remove(resolvedKeyId)
                    SystemLogger.info("Key $resolvedKeyId exhausted (USAGE_COUNT_LIMIT=$limit).")
                }
            }
        }
        val maxOps = if (securityLevel == SecurityLevel.STRONGBOX) STRONGBOX_MAX_CONCURRENT_OPS else MAX_CONCURRENT_OPS_PER_UID
        pruneOpsForUid(callingUid, softwareOperation, maxOps)
        val operationBinder = SoftwareOperationBinder(softwareOperation)
        val response = CreateOperationResponse().apply {
            iOperation = operationBinder
            operationChallenge = null
            parameters = softwareOperation.beginParameters
        }
        InterceptorUtils.createTypedObjectReply(response)
    }.getOrElse {
        SystemLogger.error("Error during createOperation for UID $callingUid.", it)
        InterceptorUtils.createServiceSpecificErrorReply(KEYMINT_UNKNOWN_ERROR)
    }

    private fun handleGenerateKey(txId: Long, callingUid: Int, callingPid: Int, data: Parcel): TransactionResult {
        val oversized = data.dataSize() > MAX_ALIAS_LENGTH
        return runCatching {
            data.enforceInterface(IKeystoreSecurityLevel.DESCRIPTOR)
            val keyDescriptor = data.readTypedObject(KeyDescriptor.CREATOR)!!
            val attestationKey = data.readTypedObject(KeyDescriptor.CREATOR)
            SystemLogger.debug("Handling generateKey ${keyDescriptor.alias}, attestKey=${attestationKey?.alias}")
            var params = data.createTypedArray(KeyParameter.CREATOR)!!
            var parsedParams = KeyMintAttestation(params)
            val isAttestKeyRequest = parsedParams.isAttestKey()
            if (ConfigurationManager.shouldSkipUid(callingUid) && attestationKey == null && !isAttestKeyRequest) {
                return TransactionResult.ContinueAndSkipPost
            }
            val challenge = parsedParams.attestationChallenge
            if (challenge != null && challenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT) {
                return InterceptorUtils.createErrorReply(KEYMINT_INVALID_INPUT_LENGTH)
            }
            if (params.any { it.tag == Tag.CREATION_DATETIME }) {
                return InterceptorUtils.createErrorReply(RESPONSE_INVALID_ARGUMENT)
            }
            if (params.any { it.tag == Tag.DEVICE_UNIQUE_ATTESTATION } && !AndroidPermissionUtils.hasUniqueIdAttestationPermission(callingUid)) {
                return InterceptorUtils.createErrorReply(KEYMINT_CANNOT_ATTEST_IDS)
            }
            val hasDeviceIdAttestation = params.any {
                it.tag == Tag.ATTESTATION_ID_IMEI || it.tag == Tag.ATTESTATION_ID_MEID ||
                it.tag == Tag.ATTESTATION_ID_SERIAL || it.tag == Tag.DEVICE_UNIQUE_ATTESTATION ||
                it.tag == Tag.ATTESTATION_ID_SECOND_IMEI
            }
            val hasDevicePropertyAttestation = parsedParams.brand != null || parsedParams.device != null ||
                parsedParams.product != null || parsedParams.manufacturer != null || parsedParams.model != null
            if ((hasDeviceIdAttestation || hasDevicePropertyAttestation) && !DeviceAttestationService.canAttestDeviceIds) {
                SystemLogger.info("[TX_ID: $txId] Real TEE cannot attest device IDs; returning CANNOT_ATTEST_IDS")
                return InterceptorUtils.createErrorReply(KEYMINT_CANNOT_ATTEST_IDS)
            }
            if (hasDeviceIdAttestation && !AndroidPermissionUtils.hasDeviceAttestationPermission(callingUid)) {
                return InterceptorUtils.createErrorReply(KEYMINT_CANNOT_ATTEST_IDS)
            }
            if (params.any { it.tag == Tag.INCLUDE_UNIQUE_ID }) {
                val hasSELinux = ConfigurationManager.checkSELinuxPermission(callingPid, "keystore_key", "gen_unique_id")
                val hasAndroid = ConfigurationManager.hasPermissionForUid(callingUid, "android.permission.REQUEST_UNIQUE_ID_ATTESTATION")
                if (!hasSELinux && !hasAndroid) {
                    params = params.filter { it.tag != Tag.INCLUDE_UNIQUE_ID }.toTypedArray()
                    parsedParams = KeyMintAttestation(params)
                }
            }
            val isSymmetric = parsedParams.algorithm == Algorithm.AES ||
                parsedParams.algorithm == Algorithm.HMAC || parsedParams.algorithm == Algorithm.TRIPLE_DES
            if (securityLevel == SecurityLevel.STRONGBOX && !isStrongBoxCapable(parsedParams)) {
                return TransactionResult.ContinueAndSkipPost
            }
            val keyId = KeyIdentifier(callingUid, keyDescriptor.alias)
            val forceGenerate = oversized || ConfigurationManager.shouldGenerate(callingUid) ||
                isAttestKeyRequest || attestationKey != null
            when {
                forceGenerate -> doSoftwareKeyGen(callingUid, keyDescriptor, attestationKey, parsedParams, keyId, isAttestKeyRequest)
                parsedParams.attestationChallenge != null -> TransactionResult.Continue
                else -> { cleanupKeyData(keyId); TransactionResult.Continue }
            }
        }.getOrElse {
            SystemLogger.error("Error during generateKey handling for UID $callingUid.", it)
            InterceptorUtils.createServiceSpecificErrorReply(SECURE_HW_COMMUNICATION_FAILED)
        }
    }

    private fun doSoftwareKeyGen(
        callingUid: Int, keyDescriptor: KeyDescriptor, attestationKey: KeyDescriptor?,
        parsedParams: KeyMintAttestation, keyId: KeyIdentifier, isAttestKeyRequest: Boolean,
    ): TransactionResult {
        val genStartNanos = System.nanoTime()
        keyDescriptor.nspace = secureRandom.nextLong()
        SystemLogger.info("Generating software key for ${keyDescriptor.alias}[${keyDescriptor.nspace}].")
        cleanupKeyData(keyId)
        val isSymmetric = parsedParams.algorithm != Algorithm.EC && parsedParams.algorithm != Algorithm.RSA
        if (isSymmetric) {
            if (attestationKey != null) {
                throw android.os.ServiceSpecificException(KEYMINT_INVALID_ARGUMENT,
                    "ATTEST_KEY tag is not supported for symmetric algorithms")
            }
            val algoName = when (parsedParams.algorithm) {
                Algorithm.AES -> "AES"
                Algorithm.HMAC -> "HmacSHA256"
                else -> throw android.os.ServiceSpecificException(KEYMINT_INVALID_ARGUMENT,
                    "Unsupported symmetric algorithm: ${parsedParams.algorithm}")
            }
            val keyGen = javax.crypto.KeyGenerator.getInstance(algoName)
            keyGen.init(parsedParams.keySize)
            val secretKey = keyGen.generateKey()
            val metadata = KeyMetadata().apply {
                keySecurityLevel = securityLevel
                key = KeyDescriptor().apply { domain = Domain.KEY_ID; nspace = keyDescriptor.nspace; alias = null; blob = null }
                certificate = null; certificateChain = null
                authorizations = parsedParams.toAuthorizations(callingUid, securityLevel)
                modificationTimeMs = System.currentTimeMillis()
            }
            val response = KeyEntryResponse().apply { this.metadata = metadata; iSecurityLevel = original }
            generatedKeys[keyId] = GeneratedKeyInfo(null, secretKey, keyDescriptor.nspace, response, parsedParams)
            Keystore2Interceptor.forgetDeletedKey(keyId)
            val metadataBytesForSymmetric = runCatching {
                android.os.Parcel.obtain().let { p -> try { metadata.writeToParcel(p, 0); p.marshall() } finally { p.recycle() } }
            }.getOrNull()
            persistExecutor.execute {
                GeneratedKeyPersistence.save(keyId, null, secretKey, keyDescriptor.nspace, securityLevel,
                    emptyList(), parsedParams.algorithm, parsedParams.keySize, parsedParams.ecCurve ?: 0,
                    parsedParams.purpose, parsedParams.digest, false, metadataBytesForSymmetric)
            }
            if (securityLevel == SecurityLevel.STRONGBOX) {
                val delayMs = STRONGBOX_KEYGEN_LATENCY_FLOOR_MS - (System.nanoTime() - genStartNanos) / 1_000_000
                if (delayMs > 0) LockSupport.parkNanos(delayMs * 1_000_000)
            } else {
                TeeLatencySimulator.simulateGenerateKeyDelay(parsedParams.algorithm, System.nanoTime() - genStartNanos)
            }
            return InterceptorUtils.createTypedObjectReply(metadata, diagnosticTag = "gen-mode-sym")
        }
        val keyData = CertificateGenerator.generateAttestedKeyPair(
            callingUid, keyDescriptor.alias, attestationKey?.alias, parsedParams, securityLevel,
        ) ?: throw Exception("Certificate generation failed.")
        val response = buildKeyEntryResponse(callingUid, keyData.second, parsedParams, keyDescriptor)
        generatedKeys[keyId] = GeneratedKeyInfo(keyData.first, null, keyDescriptor.nspace, response, parsedParams)
        Keystore2Interceptor.forgetDeletedKey(keyId)
        if (isAttestKeyRequest) attestationKeys.add(keyId)
        val certChainCopy = keyData.second.toList()
        val metadataBytesForPersist = response.metadata?.let { md ->
            runCatching {
                android.os.Parcel.obtain().let { p -> try { md.writeToParcel(p, 0); p.marshall() } finally { p.recycle() } }
            }.getOrNull()
        }
        persistExecutor.execute {
            GeneratedKeyPersistence.save(keyId, keyData.first, null, keyDescriptor.nspace, securityLevel,
                certChainCopy, parsedParams.algorithm, parsedParams.keySize, parsedParams.ecCurve ?: 0,
                parsedParams.purpose, parsedParams.digest, isAttestKeyRequest, metadataBytesForPersist)
        }
        if (securityLevel == SecurityLevel.STRONGBOX) {
            val delayMs = STRONGBOX_KEYGEN_LATENCY_FLOOR_MS - (System.nanoTime() - genStartNanos) / 1_000_000
            if (delayMs > 0) LockSupport.parkNanos(delayMs * 1_000_000)
        } else {
            TeeLatencySimulator.simulateGenerateKeyDelay(parsedParams.algorithm, System.nanoTime() - genStartNanos)
        }
        return InterceptorUtils.createTypedObjectReply(response.metadata, diagnosticTag = "gen-mode-asym")
    }

    private fun buildKeyEntryResponse(
        callingUid: Int, chain: List<Certificate>, params: KeyMintAttestation, descriptor: KeyDescriptor,
    ): KeyEntryResponse {
        val normalizedKeyDescriptor = KeyDescriptor().apply {
            domain = Domain.KEY_ID; nspace = descriptor.nspace; alias = null; blob = null
        }
        val metadata = KeyMetadata().apply {
            keySecurityLevel = securityLevel
            key = normalizedKeyDescriptor
            CertificateHelper.updateCertificateChain(this, chain.toTypedArray()).getOrThrow()
            authorizations = params.toAuthorizations(callingUid, securityLevel)
            modificationTimeMs = System.currentTimeMillis()
        }
        return KeyEntryResponse().apply { this.metadata = metadata; iSecurityLevel = original }
    }

    fun loadPersistedKeys() {
        val records = GeneratedKeyPersistence.loadAll(securityLevel)
        if (records.isEmpty()) return
        SystemLogger.info("Restoring ${records.size} persisted keys for security level $securityLevel")
        for (record in records) {
            runCatching {
                val keyId = KeyIdentifier(record.uid, record.alias)
                if (generatedKeys.containsKey(keyId)) return@runCatching
                val isSymmetric = record.symmetricKeyBytes.isNotEmpty()
                if (isSymmetric) {
                    val secretKey = javax.crypto.spec.SecretKeySpec(record.symmetricKeyBytes, record.symmetricAlgorithm)
                    val response = if (record.metadataBytes.isNotEmpty()) {
                        runCatching {
                            val parcel = android.os.Parcel.obtain()
                            try {
                                parcel.unmarshall(record.metadataBytes, 0, record.metadataBytes.size)
                                parcel.setDataPosition(0)
                                val metadata = KeyMetadata.CREATOR.createFromParcel(parcel)
                                KeyEntryResponse().apply { this.metadata = metadata; iSecurityLevel = original }
                            } finally { parcel.recycle() }
                        }.getOrElse { rebuildSymmetricResponse(record) }
                    } else rebuildSymmetricResponse(record)
                    generatedKeys[keyId] = GeneratedKeyInfo(null, secretKey, record.nspace, response,
                        response.metadata?.let { md -> KeyMintAttestation(md.authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()) })
                    return@runCatching
                }
                val algorithmName = when (record.algorithm) {
                    Algorithm.EC -> "EC"; Algorithm.RSA -> "RSA"
                    else -> throw IllegalArgumentException("Unknown algorithm: ${record.algorithm}")
                }
                val keyFactory = KeyFactory.getInstance(algorithmName)
                val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(record.privateKeyBytes))
                val certFactory = CertificateFactory.getInstance("X.509")
                val certChain = record.certChainBytes.map { certFactory.generateCertificate(ByteArrayInputStream(it)) }
                require(certChain.isNotEmpty()) { "Persisted key has empty certificate chain" }
                val publicKey = certChain[0].publicKey
                val keyPair = KeyPair(publicKey, privateKey)
                val descriptor = KeyDescriptor().apply { domain = Domain.APP; nspace = record.nspace; alias = record.alias; blob = null }
                val response = if (record.metadataBytes.isNotEmpty()) {
                    runCatching {
                        val parcel = android.os.Parcel.obtain()
                        try {
                            parcel.unmarshall(record.metadataBytes, 0, record.metadataBytes.size)
                            parcel.setDataPosition(0)
                            val metadata = KeyMetadata.CREATOR.createFromParcel(parcel)
                            metadata.key = metadata.key ?: KeyDescriptor().apply {
                                domain = Domain.KEY_ID; nspace = record.nspace; alias = null; blob = null
                            }
                            KeyEntryResponse().apply { this.metadata = metadata; iSecurityLevel = original }
                        } finally { parcel.recycle() }
                    }.getOrElse { rebuildResponseFromRecord(record, certChain, descriptor) }
                } else rebuildResponseFromRecord(record, certChain, descriptor)
                generatedKeys[keyId] = GeneratedKeyInfo(keyPair, null, record.nspace, response,
                    response.metadata?.let { md -> KeyMintAttestation(md.authorizations?.map { it.keyParameter }?.toTypedArray() ?: emptyArray()) })
                if (record.isAttestationKey) attestationKeys.add(keyId)
            }.onFailure { SystemLogger.error("Failed to restore key: uid=${record.uid} alias=${record.alias}", it) }
        }
        SystemLogger.info("Key restoration complete. Total in memory: ${generatedKeys.size}")
    }

    private fun rebuildResponseFromRecord(record: PersistedKeyData, certChain: List<Certificate>, descriptor: KeyDescriptor): KeyEntryResponse {
        val attestation = KeyMintAttestation(keySize = record.keySize, algorithm = record.algorithm,
            ecCurve = record.ecCurve, ecCurveName = "", origin = null, blockMode = emptyList(),
            padding = emptyList(), purpose = record.purposes, digest = record.digests,
            rsaPublicExponent = null, certificateSerial = null, certificateSubject = null,
            certificateNotBefore = null, certificateNotAfter = null, attestationChallenge = null,
            brand = null, device = null, product = null, serial = null, imei = null, meid = null,
            manufacturer = null, model = null, secondImei = null, activeDateTime = null,
            originationExpireDateTime = null, usageExpireDateTime = null, usageCountLimit = null,
            callerNonce = null, nonce = null, unlockedDeviceRequired = null, includeUniqueId = null,
            rollbackResistance = null, earlyBootOnly = null, allowWhileOnBody = null,
            trustedUserPresenceRequired = null, trustedConfirmationRequired = null,
            noAuthRequired = null, maxUsesPerBoot = null, maxBootLevel = null, minMacLength = null,
            rsaOaepMgfDigest = emptyList())
        return buildKeyEntryResponse(record.uid, certChain, attestation, descriptor)
    }

    private fun rebuildSymmetricResponse(record: PersistedKeyData): KeyEntryResponse {
        val attestation = KeyMintAttestation(keySize = record.keySize, algorithm = record.algorithm,
            ecCurve = record.ecCurve, ecCurveName = "", origin = null, blockMode = emptyList(),
            padding = emptyList(), purpose = record.purposes, digest = record.digests,
            rsaPublicExponent = null, certificateSerial = null, certificateSubject = null,
            certificateNotBefore = null, certificateNotAfter = null, attestationChallenge = null,
            brand = null, device = null, product = null, serial = null, imei = null, meid = null,
            manufacturer = null, model = null, secondImei = null, activeDateTime = null,
            originationExpireDateTime = null, usageExpireDateTime = null, usageCountLimit = null,
            callerNonce = null, nonce = null, unlockedDeviceRequired = null, includeUniqueId = null,
            rollbackResistance = null, earlyBootOnly = null, allowWhileOnBody = null,
            trustedUserPresenceRequired = null, trustedConfirmationRequired = null,
            noAuthRequired = null, maxUsesPerBoot = null, maxBootLevel = null, minMacLength = null,
            rsaOaepMgfDigest = emptyList())
        val metadata = KeyMetadata().apply {
            keySecurityLevel = securityLevel
            key = KeyDescriptor().apply { domain = Domain.KEY_ID; nspace = record.nspace; alias = null; blob = null }
            certificate = null; certificateChain = null
            authorizations = attestation.toAuthorizations(record.uid, securityLevel)
            modificationTimeMs = System.currentTimeMillis()
        }
        return KeyEntryResponse().apply { this.metadata = metadata; iSecurityLevel = original }
    }

    companion object {
        private val secureRandom = SecureRandom()
        private const val MAX_ALIAS_LENGTH = 256 * 1024
        private const val KEYMINT_INVALID_INPUT_LENGTH = -21
        private const val KEYMINT_INVALID_ARGUMENT = -38
        private const val RESPONSE_INVALID_ARGUMENT = 20
        private const val RESPONSE_PERMISSION_DENIED = 6
        private const val RESPONSE_KEY_NOT_FOUND = 7
        private const val STRONGBOX_KEYGEN_LATENCY_FLOOR_MS = 250L
        private const val STRONGBOX_OP_LATENCY_FLOOR_MS = 80L
        private const val TEE_OP_LATENCY_FLOOR_MS = 4L
        private const val KEYMINT_TOO_MANY_OPERATIONS = -29
        private const val KEYMINT_CANNOT_ATTEST_IDS = -66
        private const val KEYMINT_UNKNOWN_ERROR = -1000
        private const val SECURE_HW_COMMUNICATION_FAILED = -49
        private const val MAX_CONCURRENT_OPS_PER_UID = 15
        private const val STRONGBOX_MAX_CONCURRENT_OPS = 4
        private const val STRONGBOX_OP_WINDOW_NS = 10_000_000_000L

        private fun isStrongBoxCapable(params: KeyMintAttestation): Boolean = when (params.algorithm) {
            Algorithm.RSA -> params.keySize <= 2048
            Algorithm.EC -> params.ecCurve == null || params.ecCurve == EcCurve.P_256
            else -> true
        }

        private val GENERATE_KEY_TRANSACTION = InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "generateKey")
        private val IMPORT_KEY_TRANSACTION = InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "importKey")
        private val CREATE_OPERATION_TRANSACTION = InterceptorUtils.getTransactCode(IKeystoreSecurityLevel.Stub::class.java, "createOperation")

        val INTERCEPTED_CODES = intArrayOf(GENERATE_KEY_TRANSACTION, IMPORT_KEY_TRANSACTION, CREATE_OPERATION_TRANSACTION)

        private val transactionNames: Map<Int, String> by lazy {
            IKeystoreSecurityLevel.Stub::class.java.declaredFields
                .filter { it.isAccessible = true; it.type == Int::class.java && it.name.startsWith("TRANSACTION_") }
                .associate { field -> (field.get(null) as Int) to field.name.split("_")[1] }
        }

        private val persistExecutor = Executors.newSingleThreadExecutor()

        val generatedKeys = ConcurrentHashMap<KeyIdentifier, GeneratedKeyInfo>()
        val teeResponses = ConcurrentHashMap<KeyIdentifier, KeyEntryResponse>()
        val patchedChains = ConcurrentHashMap<KeyIdentifier, Array<Certificate>>()
        val attestationKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
        val importedKeys: MutableSet<KeyIdentifier> = ConcurrentHashMap.newKeySet()
        private val usageCounters = ConcurrentHashMap<KeyIdentifier, AtomicInteger>()
        private val interceptedOperations = ConcurrentHashMap<IBinder, OperationInterceptor>()

        data class SoftwareGrant(val ownerKeyId: KeyIdentifier, val granteeUid: Int, val accessVector: Int)
        val softwareGrants = ConcurrentHashMap<Long, SoftwareGrant>()

        fun issueGrant(ownerKeyId: KeyIdentifier, granteeUid: Int, accessVector: Int): Long {
            softwareGrants.entries.firstOrNull { it.value.ownerKeyId == ownerKeyId && it.value.granteeUid == granteeUid }?.let { existing ->
                softwareGrants[existing.key] = existing.value.copy(accessVector = accessVector)
                return existing.key
            }
            var id = secureRandom.nextLong()
            while (id == 0L || id == -1L || softwareGrants.containsKey(id)) id = secureRandom.nextLong()
            softwareGrants[id] = SoftwareGrant(ownerKeyId, granteeUid, accessVector)
            return id
        }

        fun resolveGrant(grantId: Long, callerUid: Int): SoftwareGrant? =
            softwareGrants[grantId]?.takeIf { it.granteeUid == callerUid && ownsKeyResponse(it.ownerKeyId) }

        fun ownsKeyResponse(keyId: KeyIdentifier): Boolean = getGeneratedKeyResponse(keyId) != null

        fun revokeGrant(ownerKeyId: KeyIdentifier, granteeUid: Int) {
            softwareGrants.entries.filter { it.value.ownerKeyId == ownerKeyId && it.value.granteeUid == granteeUid }
                .forEach { softwareGrants.remove(it.key) }
        }

        fun purgeGrantsForKey(ownerKeyId: KeyIdentifier) {
            softwareGrants.entries.filter { it.value.ownerKeyId == ownerKeyId }.forEach { softwareGrants.remove(it.key) }
        }

        fun getGeneratedKeyResponse(keyId: KeyIdentifier): KeyEntryResponse? =
            generatedKeys[keyId]?.response ?: teeResponses[keyId]

        fun findGeneratedKeyByKeyId(callingUid: Int, nspace: Long?): GeneratedKeyInfo? {
            if (nspace == null || nspace == 0L) return null
            return generatedKeys.entries.filter { (k, _) -> k.uid == callingUid }.find { (_, info) -> info.nspace == nspace }?.value
        }

        fun findTeeResponseByKeyId(callingUid: Int, nspace: Long?): KeyEntryResponse? {
            if (nspace == null || nspace == 0L) return null
            return teeResponses.entries.filter { (k, _) -> k.uid == callingUid }.find { (_, r) -> r.metadata?.key?.nspace == nspace }?.value
        }

        fun evictTeeResponseByKeyId(callingUid: Int, nspace: Long?) {
            if (nspace == null || nspace == 0L) return
            teeResponses.entries.filter { (k, _) -> k.uid == callingUid }.find { (_, r) -> r.metadata?.key?.nspace == nspace }?.let { evictTeeResponse(it.key) }
        }

        fun evictTeeResponse(keyId: KeyIdentifier) { teeResponses.remove(keyId); patchedChains.remove(keyId) }
        fun getPatchedChain(keyId: KeyIdentifier): Array<Certificate>? = patchedChains[keyId]
        fun isAttestationKey(keyId: KeyIdentifier): Boolean = attestationKeys.contains(keyId)

        fun cleanupKeyData(keyId: KeyIdentifier) {
            purgeGrantsForKey(keyId)
            if (generatedKeys.remove(keyId) != null) { GeneratedKeyPersistence.delete(keyId) }
            teeResponses.remove(keyId)
            patchedChains.remove(keyId)
            attestationKeys.remove(keyId)
            importedKeys.remove(keyId)
            usageCounters.remove(keyId)
        }

        fun clearNamespaceKeys(uid: Int) {
            val victims = generatedKeys.keys.filter { it.uid == uid }
            if (victims.isEmpty()) return
            victims.forEach { cleanupKeyData(it) }
            SystemLogger.info("Cleared ${victims.size} synthetic keys for uid=$uid (maintenance.clearNamespace)")
        }

        fun migrateGeneratedKey(srcId: KeyIdentifier, dstId: KeyIdentifier) {
            if (srcId == dstId || generatedKeys.containsKey(dstId)) return
            val info = generatedKeys.remove(srcId) ?: return
            generatedKeys[dstId] = info
            if (attestationKeys.remove(srcId)) attestationKeys.add(dstId)
            if (importedKeys.remove(srcId)) importedKeys.add(dstId)
            softwareGrants.entries.filter { it.value.ownerKeyId == srcId }.forEach { softwareGrants[it.key] = it.value.copy(ownerKeyId = dstId) }
            GeneratedKeyPersistence.delete(srcId)
            SystemLogger.info("Migrated synthetic key $srcId -> $dstId")
        }

        fun removeOperationInterceptor(operationBinder: IBinder, backdoor: IBinder) {
            unregister(backdoor, operationBinder)
            interceptedOperations.remove(operationBinder)
        }

        fun invalidatePatchedChains(reason: String? = null) {
            val count = patchedChains.size
            if (count == 0) return
            patchedChains.clear()
            SystemLogger.info("Invalidated $count patched cert chains${reason?.let { " due to $it" } ?: ""}.")
        }

        fun clearAllGeneratedKeys(reason: String? = null) {
            val count = generatedKeys.size
            generatedKeys.clear(); teeResponses.clear(); patchedChains.clear()
            attestationKeys.clear(); importedKeys.clear(); usageCounters.clear(); softwareGrants.clear()
            GeneratedKeyPersistence.deleteAll()
            SystemLogger.info("Cleared all cached keys ($count entries)${reason?.let { " due to $it" } ?: ""}.")
        }
    }
}

private fun KeyMintAttestation.toAuthorizations(callingUid: Int, secLevel: Int): Array<Authorization> {
    val authList = mutableListOf<Authorization>()
    fun createAuth(tag: Int, value: KeyParameterValue): Authorization = Authorization().apply {
        keyParameter = KeyParameter().apply { this.tag = tag; this.value = value }
        this.securityLevel = secLevel
    }
    fun createKeystoreAuth(tag: Int, value: KeyParameterValue): Authorization = Authorization().apply {
        keyParameter = KeyParameter().apply { this.tag = tag; this.value = value }
        this.securityLevel = SecurityLevel.KEYSTORE
    }

    this.purpose.forEach { authList.add(createAuth(Tag.PURPOSE, KeyParameterValue.keyPurpose(it))) }
    authList.add(createAuth(Tag.ALGORITHM, KeyParameterValue.algorithm(this.algorithm)))
    authList.add(createAuth(Tag.KEY_SIZE, KeyParameterValue.integer(this.keySize)))
    if (this.ecCurve != null) authList.add(createAuth(Tag.EC_CURVE, KeyParameterValue.ecCurve(this.ecCurve)))
    this.blockMode.forEach { authList.add(createAuth(Tag.BLOCK_MODE, KeyParameterValue.blockMode(it))) }
    this.digest.forEach { authList.add(createAuth(Tag.DIGEST, KeyParameterValue.digest(it))) }
    this.padding.forEach { authList.add(createAuth(Tag.PADDING, KeyParameterValue.paddingMode(it))) }
    if (this.rsaPublicExponent != null) authList.add(createAuth(Tag.RSA_PUBLIC_EXPONENT, KeyParameterValue.longInteger(this.rsaPublicExponent.toLong())))
    if (this.callerNonce == true) authList.add(createAuth(Tag.CALLER_NONCE, KeyParameterValue.boolValue(true)))
    if (this.minMacLength != null) authList.add(createAuth(Tag.MIN_MAC_LENGTH, KeyParameterValue.integer(this.minMacLength)))
    if (this.rollbackResistance == true) authList.add(createAuth(Tag.ROLLBACK_RESISTANCE, KeyParameterValue.boolValue(true)))
    if (this.earlyBootOnly == true) authList.add(createAuth(Tag.EARLY_BOOT_ONLY, KeyParameterValue.boolValue(true)))
    if (this.allowWhileOnBody == true) authList.add(createAuth(Tag.ALLOW_WHILE_ON_BODY, KeyParameterValue.boolValue(true)))
    if (this.trustedUserPresenceRequired == true) authList.add(createAuth(Tag.TRUSTED_USER_PRESENCE_REQUIRED, KeyParameterValue.boolValue(true)))
    if (this.trustedConfirmationRequired == true) authList.add(createAuth(Tag.TRUSTED_CONFIRMATION_REQUIRED, KeyParameterValue.boolValue(true)))
    if (this.maxUsesPerBoot != null) authList.add(createAuth(Tag.MAX_USES_PER_BOOT, KeyParameterValue.integer(this.maxUsesPerBoot)))
    if (this.maxBootLevel != null) authList.add(createAuth(Tag.MAX_BOOT_LEVEL, KeyParameterValue.integer(this.maxBootLevel)))
    if (this.noAuthRequired != false) authList.add(createAuth(Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true)))
    authList.add(createAuth(Tag.ORIGIN, KeyParameterValue.origin(this.origin ?: KeyOrigin.GENERATED)))
    authList.add(createAuth(Tag.OS_VERSION, KeyParameterValue.integer(AndroidDeviceUtils.osVersion)))
    val osPatch = AndroidDeviceUtils.getPatchLevel(callingUid)
    if (osPatch != AndroidDeviceUtils.DO_NOT_REPORT) authList.add(createAuth(Tag.OS_PATCHLEVEL, KeyParameterValue.integer(osPatch)))
    authList.add(createKeystoreAuth(Tag.CREATION_DATETIME, KeyParameterValue.dateTime(System.currentTimeMillis())))
    this.activeDateTime?.let { authList.add(createKeystoreAuth(Tag.ACTIVE_DATETIME, KeyParameterValue.dateTime(it.time))) }
    this.originationExpireDateTime?.let { authList.add(createKeystoreAuth(Tag.ORIGINATION_EXPIRE_DATETIME, KeyParameterValue.dateTime(it.time))) }
    this.usageExpireDateTime?.let { authList.add(createKeystoreAuth(Tag.USAGE_EXPIRE_DATETIME, KeyParameterValue.dateTime(it.time))) }
    this.usageCountLimit?.let { authList.add(createKeystoreAuth(Tag.USAGE_COUNT_LIMIT, KeyParameterValue.integer(it))) }
    if (this.unlockedDeviceRequired == true) authList.add(createKeystoreAuth(Tag.UNLOCKED_DEVICE_REQUIRED, KeyParameterValue.boolValue(true)))
    authList.add(Authorization().apply {
        keyParameter = KeyParameter().apply { this.tag = Tag.USER_ID; this.value = KeyParameterValue.integer(callingUid / 100000) }
        this.securityLevel = SecurityLevel.SOFTWARE
    })
    return authList.toTypedArray()
}
