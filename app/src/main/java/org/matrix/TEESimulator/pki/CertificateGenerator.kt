package org.matrix.TEESimulator.pki

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.KeyPurpose
import android.os.Build
import android.util.Pair
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.TEESimulator.attestation.AttestationBuilder
import org.matrix.TEESimulator.attestation.AttestationConstants
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

object CertificateGenerator {

    /** RFC 5280 GeneralizedTime max: 9999-12-31 23:59:59 UTC */
    private const val UNDEFINED_NOT_AFTER = 253402300799000L

    fun generateSoftwareKeyPair(params: KeyMintAttestation): KeyPair? {
        return runCatching {
                val (algorithm, spec) =
                    when (params.algorithm) {
                        Algorithm.EC -> "EC" to ECGenParameterSpec(params.ecCurveName)
                        Algorithm.RSA ->
                            "RSA" to
                                RSAKeyGenParameterSpec(
                                    params.keySize,
                                    params.rsaPublicExponent ?: RSAKeyGenParameterSpec.F4,
                                )
                        else ->
                            throw IllegalArgumentException(
                                "Unsupported algorithm: ${params.algorithm}"
                            )
                    }
                KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME)
                    .apply { initialize(spec) }
                    .generateKeyPair()
            }
            .onFailure { SystemLogger.error("Failed to generate software key pair.", it) }
            .getOrNull()
    }

    /**
     * Generates a certificate chain for a given key pair.
     *
     * AOSP ta/src/keys.rs:451-478: when no attestation challenge and no attestKey are
     * provided, returns a self-signed leaf certificate (depth 1) with no attestation
     * extension. This matches real KeyMint HAL behavior.
     *
     * When BYO attest key lookup misses, include the full keybox certificate chain
     * so the chain is rooted (not just a depth-1 chain signed by keybox root with no
     * parent attached — which would be structurally invalid).
     */
    fun generateCertificateChain(
        uid: Int,
        subjectKeyPair: KeyPair,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): List<Certificate>? {
        val challenge = params.attestationChallenge
        if (challenge != null && challenge.size > AttestationConstants.CHALLENGE_LENGTH_LIMIT)
            throw IllegalArgumentException(
                "Attestation challenge exceeds length limit (${challenge.size} > ${AttestationConstants.CHALLENGE_LENGTH_LIMIT})"
            )

        return try {
                // AOSP: no challenge + no attestKey = self-signed, depth 1
                if (challenge == null && attestKeyAlias == null) {
                    return listOf(buildSelfSignedCertificate(subjectKeyPair, params))
                }

                val keybox = getKeyboxForAlgorithm(uid, params.algorithm)

                val attestKeyInfo =
                    if (attestKeyAlias != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        getAttestationKeyInfo(uid, attestKeyAlias)
                    } else null

                val (signingKey, issuer) = attestKeyInfo
                    ?.let { it.first to it.second }
                    ?: (keybox.keyPair to getIssuerFromKeybox(keybox))

                val leafCert =
                    buildCertificate(subjectKeyPair, signingKey, issuer, params, uid, securityLevel)

                if (attestKeyInfo != null) {
                    // BYO hit: caller holds the rest of the chain
                    listOf(leafCert)
                } else {
                    // BYO miss: include keybox.certificates so chain is rooted
                    listOf(leafCert) + keybox.certificates
                }
            } catch (e: android.os.ServiceSpecificException) {
                throw e
            } catch (e: Exception) {
                SystemLogger.error("Failed to generate certificate chain.", e)
                null
            }
    }

    fun generateAttestedKeyPair(
        uid: Int,
        alias: String,
        attestKeyAlias: String?,
        params: KeyMintAttestation,
        securityLevel: Int,
    ): Pair<KeyPair, List<Certificate>>? {
        return try {
                val newKeyPair =
                    generateSoftwareKeyPair(params)
                        ?: throw Exception("Failed to generate underlying software key pair.")
                val chain =
                    generateCertificateChain(uid, newKeyPair, attestKeyAlias, params, securityLevel)
                        ?: throw Exception("Failed to generate certificate chain for new key pair.")
                Pair(newKeyPair, chain)
            } catch (e: android.os.ServiceSpecificException) {
                throw e
            } catch (e: Exception) {
                SystemLogger.error("Failed to generate attested key pair for alias '$alias'.", e)
                null
            }
    }

    fun getIssuerFromKeybox(keybox: KeyBox) =
        X509CertificateHolder(keybox.certificates[0].encoded).subject

    private fun getKeyboxForAlgorithm(uid: Int, algorithm: Int): KeyBox {
        val keyboxFile = ConfigurationManager.getKeyboxFileForUid(uid)
        val algorithmName =
            when (algorithm) {
                Algorithm.EC -> "EC"
                Algorithm.RSA -> "RSA"
                else -> throw IllegalArgumentException("Unsupported algorithm ID: $algorithm")
            }
        return KeyBoxManager.getAttestationKey(keyboxFile, algorithmName)
            ?: throw android.os.ServiceSpecificException(
                -75,
                "No attestation key for algorithm $algorithmName in $keyboxFile",
            )
    }

    private fun getAttestationKeyInfo(uid: Int, attestKeyAlias: String): Pair<KeyPair, X500Name>? {
        val keyId = KeyIdentifier(uid, attestKeyAlias)
        val keyInfo = KeyMintSecurityLevelInterceptor.generatedKeys[keyId]
        return if (keyInfo != null) {
            val certChain = CertificateHelper.getCertificateChain(keyInfo.response)
            if (!certChain.isNullOrEmpty()) {
                val issuer = X509CertificateHolder(certChain[0].encoded).subject
                Pair(keyInfo.keyPair, issuer)
            } else {
                null
            }
        } else {
            null
        }
    }

    /** Maps KeyPurpose values to X.509 KeyUsage bits per KeyCreationResult.aidl spec */
    private fun buildKeyUsageFromPurposes(purposes: List<Int>): Int {
        var bits = 0
        for (purpose in purposes) {
            bits = bits or when (purpose) {
                KeyPurpose.SIGN -> KeyUsage.digitalSignature
                KeyPurpose.DECRYPT -> KeyUsage.dataEncipherment
                KeyPurpose.WRAP_KEY -> KeyUsage.keyEncipherment
                KeyPurpose.AGREE_KEY -> KeyUsage.keyAgreement
                KeyPurpose.ATTEST_KEY -> KeyUsage.keyCertSign
                else -> 0
            }
        }
        return bits
    }

    private fun buildCertificate(
        subjectKeyPair: KeyPair,
        signingKeyPair: KeyPair,
        issuer: X500Name,
        params: KeyMintAttestation,
        uid: Int,
        securityLevel: Int,
    ): Certificate {
        val subject = params.certificateSubject ?: X500Name("CN=Android Keystore Key")
        val notBefore = params.certificateNotBefore ?: Date(0)
        val notAfter = params.certificateNotAfter ?: Date(UNDEFINED_NOT_AFTER)

        val builder =
            JcaX509v3CertificateBuilder(
                issuer,
                params.certificateSerial ?: BigInteger.ONE,
                notBefore,
                notAfter,
                subject,
                subjectKeyPair.public,
            )

        val keyUsageBits = buildKeyUsageFromPurposes(params.purpose)
        if (keyUsageBits != 0) {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
        }
        if (params.attestationChallenge != null) {
            builder.addExtension(
                AttestationBuilder.buildAttestationExtension(params, uid, securityLevel)
            )
        }

        // Signing algorithm must match the signing key's type, not the subject key's.
        val signerAlgorithm =
            when (signingKeyPair.private.algorithm) {
                "EC", "ECDSA" -> "SHA256withECDSA"
                "RSA" -> "SHA256withRSA"
                else -> throw IllegalArgumentException("Unsupported signing key: ${signingKeyPair.private.algorithm}")
            }
        val contentSigner =
            JcaContentSignerBuilder(signerAlgorithm)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(signingKeyPair.private)

        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }

    /**
     * AOSP ta/src/keys.rs:452-478, ta/src/cert.rs:111-114:
     * Self-signed leaf (depth 1) for non-attested keys. subject==issuer,
     * signed by the generated key itself, no attestation extension.
     */
    private fun buildSelfSignedCertificate(
        keyPair: KeyPair,
        params: KeyMintAttestation,
    ): Certificate {
        val subject = params.certificateSubject ?: X500Name("CN=Android Keystore Key")
        val notBefore = params.certificateNotBefore ?: Date(0)
        val notAfter = params.certificateNotAfter ?: Date(UNDEFINED_NOT_AFTER)

        val builder = JcaX509v3CertificateBuilder(
            subject,
            params.certificateSerial ?: BigInteger.ONE,
            notBefore,
            notAfter,
            subject,
            keyPair.public,
        )

        val keyUsageBits = buildKeyUsageFromPurposes(params.purpose)
        if (keyUsageBits != 0) {
            builder.addExtension(Extension.keyUsage, true, KeyUsage(keyUsageBits))
        }

        val signerAlgorithm = when (keyPair.private.algorithm) {
            "EC", "ECDSA" -> "SHA256withECDSA"
            "RSA" -> "SHA256withRSA"
            else -> throw IllegalArgumentException("Unsupported key: ${keyPair.private.algorithm}")
        }
        val contentSigner = JcaContentSignerBuilder(signerAlgorithm)
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.private)

        return JcaX509CertificateConverter().getCertificate(builder.build(contentSigner))
    }
}
