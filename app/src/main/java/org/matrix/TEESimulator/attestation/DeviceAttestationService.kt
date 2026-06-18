package org.matrix.TEESimulator.attestation

import android.annotation.SuppressLint
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.toHex

val ATTESTATION_OID: ASN1ObjectIdentifier = ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")

@SuppressLint("PrivateApi")
object DeviceAttestationService {

    data class AttestationData(
        val moduleHash: ByteArray?,
        val verifiedBootKey: ByteArray?,
        val verifiedBootHash: ByteArray?,
        val attestVersion: Int?,
        val keymasterVersion: Int?,
        val osVersion: Int?,
        val osPatchLevel: Int?,
        val vendorPatchLevel: Int?,
        val bootPatchLevel: Int?,
    )

    private const val TEE_CHECK_KEY_ALIAS = "TEESimulator_AttestationCheck"
    private const val DEVICE_ID_CHECK_KEY_ALIAS = "TEESimulator_DeviceIdCheck"

    val isTeeFunctional: Boolean by lazy { checkTeeFunctionality() }

    /**
     * Lazily mirrors whether the real TEE can attest device identifiers/properties.
     * Hardware that never provisioned device IDs returns CANNOT_ATTEST_IDS; the
     * synthesizer consults this so it never forges a capability the real silicon
     * lacks. Cached.
     */
    val canAttestDeviceIds: Boolean by lazy { checkDeviceIdAttestation() }

    val CachedAttestationData: AttestationData? by lazy { fetchAttestationData() }

    private fun checkTeeFunctionality(): Boolean {
        SystemLogger.info("Performing TEE functionality check...")
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val challenge = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            val spec =
                KeyGenParameterSpec.Builder(TEE_CHECK_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .build()
            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()
            SystemLogger.info("TEE functionality check successful.")
            true
        } catch (e: Exception) {
            SystemLogger.warning("TEE functionality check failed.", e)
            false
        }
    }

    /**
     * Probes whether the real TEE can satisfy device-ID/property attestation,
     * mirroring its actual capability. Gated behind [isTeeFunctional] so a dead
     * TEE never triggers a second doomed probe — it simply reports `false`
     * (cannot attest), the faithful result for such hardware.
     */
    private fun checkDeviceIdAttestation(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return false
        if (!isTeeFunctional) return false
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val keyPairGenerator =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val challenge = ByteArray(16).apply { SecureRandom().nextBytes(this) }
            val spec =
                KeyGenParameterSpec.Builder(DEVICE_ID_CHECK_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(challenge)
                    .setDevicePropertiesAttestationIncluded(true)
                    .build()
            keyPairGenerator.initialize(spec)
            keyPairGenerator.generateKeyPair()
            runCatching { keyStore.deleteEntry(DEVICE_ID_CHECK_KEY_ALIAS) }
            SystemLogger.info("Device-ID attestation supported by TEE.")
            true
        } catch (_: Exception) {
            SystemLogger.info("Device-ID attestation not supported by TEE; mirroring as cannot-attest.")
            false
        }
    }

    private fun getAttestationCertificate(): X509Certificate? {
        if (!isTeeFunctional) return null
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val certChain = keyStore.getCertificateChain(TEE_CHECK_KEY_ALIAS)
            if (certChain.isNullOrEmpty()) {
                SystemLogger.warning("Could not retrieve certificate chain for TEE check key.")
                null
            } else {
                keyStore.deleteEntry(TEE_CHECK_KEY_ALIAS)
                certChain[0] as X509Certificate
            }
        } catch (e: Exception) {
            SystemLogger.error("Error retrieving attestation certificate.", e)
            null
        }
    }

    private fun fetchAttestationData(): AttestationData? {
        val leafCert = getAttestationCertificate() ?: return null
        try {
            val leafHolder = X509CertificateHolder(leafCert.encoded)
            val extension: Extension =
                leafHolder.getExtension(ATTESTATION_OID) ?: return null
            val keyDescriptionSeq = ASN1Sequence.getInstance(extension.extnValue.octets)
            SystemLogger.verbose {
                val formattedString = keyDescriptionSeq.joinToString(separator = ", ") {
                    AttestationPatcher.formatAsn1Primitive(it)
                }
                "Cached attestation data: $formattedString"
            }
            val fields = keyDescriptionSeq.toArray()
            val attestVersion =
                ASN1Integer.getInstance(fields[AttestationConstants.KEY_DESCRIPTION_ATTESTATION_VERSION_INDEX])
                    .positiveValue.toInt()
            val keymasterVersion =
                ASN1Integer.getInstance(fields[AttestationConstants.KEY_DESCRIPTION_KEYMINT_VERSION_INDEX])
                    .positiveValue.toInt()
            var moduleHash: ByteArray? = null
            var verifiedBootKey: ByteArray? = null
            var verifiedBootHash: ByteArray? = null
            var osVersion: Int? = null
            var osPatchLevel: Int? = null
            var vendorPatchLevel: Int? = null
            var bootPatchLevel: Int? = null
            val softwareEnforced =
                ASN1Sequence.getInstance(fields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX])
            moduleHash =
                softwareEnforced.toArray()
                    .firstOrNull { (it as? ASN1TaggedObject)?.tagNo == AttestationConstants.TAG_MODULE_HASH }
                    ?.let { ASN1OctetString.getInstance((it as ASN1TaggedObject).baseObject).octets }
            val teeEnforced =
                ASN1Sequence.getInstance(fields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX])
            teeEnforced.forEach { element ->
                val tagged = element as ASN1TaggedObject
                when (tagged.tagNo) {
                    AttestationConstants.TAG_ROOT_OF_TRUST -> {
                        val rotSeq = ASN1Sequence.getInstance(tagged.baseObject.toASN1Primitive())
                        if (rotSeq.size() >= 4) {
                            verifiedBootKey =
                                ASN1OctetString.getInstance(rotSeq.getObjectAt(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX)).octets
                            verifiedBootHash =
                                ASN1OctetString.getInstance(rotSeq.getObjectAt(AttestationConstants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX)).octets
                        }
                    }
                    AttestationConstants.TAG_OS_VERSION ->
                        osVersion = ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).positiveValue.toInt()
                    AttestationConstants.TAG_OS_PATCHLEVEL ->
                        osPatchLevel = ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).positiveValue.toInt()
                    AttestationConstants.TAG_VENDOR_PATCHLEVEL ->
                        vendorPatchLevel = ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).positiveValue.toInt()
                    AttestationConstants.TAG_BOOT_PATCHLEVEL ->
                        bootPatchLevel = ASN1Integer.getInstance(tagged.baseObject.toASN1Primitive()).positiveValue.toInt()
                }
            }
            if (verifiedBootKey?.all { it == 0.toByte() } == true) verifiedBootKey = null
            if (verifiedBootHash?.all { it == 0.toByte() } == true) verifiedBootHash = null
            SystemLogger.info(
                "Successfully extracted attestation data: version=$attestVersion, osVersion=$osVersion, osPatch=$osPatchLevel, vendorPatch=$vendorPatchLevel, bootPatch=$bootPatchLevel, moduleHash=${moduleHash?.toHex()}, bootKey=${verifiedBootKey?.toHex()}, bootHash=${verifiedBootHash?.toHex()}"
            )
            return AttestationData(moduleHash, verifiedBootKey, verifiedBootHash, attestVersion, keymasterVersion, osVersion, osPatchLevel, vendorPatchLevel, bootPatchLevel)
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse attestation data from certificate.", e)
            return null
        }
    }
}
