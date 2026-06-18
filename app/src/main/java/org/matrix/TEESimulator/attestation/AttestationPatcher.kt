package org.matrix.TEESimulator.attestation

import android.security.keystore.KeyProperties
import java.nio.charset.StandardCharsets
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.KeyBox
import org.matrix.TEESimulator.pki.KeyBoxManager
import org.matrix.TEESimulator.util.toHex

object AttestationPatcher {

    /**
     * Patches a full certificate chain by modifying the leaf's attestation and rebuilding the chain
     * with the correct custom signing certificates.
     *
     * @param originalChain The original certificate chain from the hardware. The leaf must be at index 0.
     * @param uid The UID of the application requesting the certificate.
     * @param notBefore Optional override for the certificate's notBefore date.
     * @param notAfter Optional override for the certificate's notAfter date.
     * @return A new, cryptographically valid, patched certificate chain. Returns the original chain on any failure.
     */
    fun patchCertificateChain(
        originalChain: Array<Certificate>?,
        uid: Int,
        notBefore: Date? = null,
        notAfter: Date? = null,
    ): Array<Certificate> {
        if (originalChain.isNullOrEmpty()) {
            SystemLogger.error("Attempted to patch a null or empty certificate chain for UID $uid.")
            return originalChain ?: emptyArray()
        }

        return runCatching {
                val originalLeaf = originalChain[0] as X509Certificate
                val originalLeafHolder = X509CertificateHolder(originalLeaf.encoded)

                val parsedAttestation =
                    parseAttestationExtension(originalLeafHolder) ?: return originalChain

                val keybox = getKeyboxForUidAndAlgorithm(uid, originalLeaf.sigAlgName)

                val patchedLeaf =
                    createPatchedLeafCertificate(
                        originalLeafHolder,
                        parsedAttestation,
                        keybox,
                        originalLeaf.sigAlgName,
                        uid,
                        notBefore,
                        notAfter,
                    )

                val newChain = listOf(patchedLeaf) + keybox.certificates

                SystemLogger.info(
                    "Successfully rebuilt a valid, patched certificate chain for UID $uid."
                )
                newChain.toTypedArray()
            }
            .getOrElse {
                SystemLogger.error(
                    "Failed to patch and rebuild certificate chain for UID $uid.",
                    it,
                )
                originalChain
            }
    }

    private fun normalizeSignatureAlgorithm(algoName: String): String {
        return algoName.uppercase().replace("WITH", "with")
    }

    private fun createPatchedLeafCertificate(
        originalLeafHolder: X509CertificateHolder,
        parsedAttestation: ParsedAttestation,
        keybox: KeyBox,
        sigAlgName: String,
        uid: Int,
        notBefore: Date? = null,
        notAfter: Date? = null,
    ): Certificate {
        val newIssuer = X509CertificateHolder(keybox.certificates[0].encoded).subject

        val effectiveNotBefore = notBefore ?: originalLeafHolder.notBefore
        val effectiveNotAfter = notAfter ?: originalLeafHolder.notAfter
        if (notBefore != null || notAfter != null) {
            SystemLogger.debug(
                "Overriding cert dates: notBefore=$effectiveNotBefore (was ${originalLeafHolder.notBefore}), notAfter=$effectiveNotAfter (was ${originalLeafHolder.notAfter})"
            )
        }

        val builder =
            X509v3CertificateBuilder(
                newIssuer,
                originalLeafHolder.serialNumber,
                effectiveNotBefore,
                effectiveNotAfter,
                originalLeafHolder.subject,
                originalLeafHolder.subjectPublicKeyInfo,
            )

        val patchedExtension = createPatchedAttestationExtension(parsedAttestation, uid)

        originalLeafHolder.extensions.extensionOIDs.forEach {
            builder.addExtension(
                if (it == ATTESTATION_OID) patchedExtension else originalLeafHolder.getExtension(it)
            )
        }

        val signer =
            JcaContentSignerBuilder(normalizeSignatureAlgorithm(sigAlgName))
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keybox.keyPair.private)
        val newCertificate = JcaX509CertificateConverter().getCertificate(builder.build(signer))

        val signatureBytes = (newCertificate as X509Certificate).signature
        SystemLogger.verbose { "Signature of patched leaf cert: ${signatureBytes.toHex()}" }

        return newCertificate
    }

    private fun getKeyboxForUidAndAlgorithm(uid: Int, algorithm: String): KeyBox {
        val keyboxFile = ConfigurationManager.getKeyboxFileForUid(uid)
        val keyType =
            when {
                algorithm.contains("RSA", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_RSA
                algorithm.contains("EC", ignoreCase = true) -> KeyProperties.KEY_ALGORITHM_EC
                else -> algorithm
            }
        return KeyBoxManager.getAttestationKey(keyboxFile, keyType)
            ?: throw IllegalArgumentException(
                "No keybox found for UID $uid and algorithm '$keyType' (derived from input '$algorithm') in file $keyboxFile"
            )
    }

    fun formatAsn1Primitive(obj: ASN1Encodable?): String {
        val primitive = obj?.toASN1Primitive()
        return when (primitive) {
            null -> "NULL"
            is ASN1Integer -> primitive.value.toString()
            is ASN1Enumerated -> primitive.value.toString()
            is ASN1Boolean -> primitive.isTrue.toString()
            is ASN1Null -> "NULL"
            is ASN1OctetString -> {
                val bytes = primitive.octets
                if (bytes.all { it >= 32 && it < 127 }) {
                    "\"${String(bytes, StandardCharsets.UTF_8)}\""
                } else if (bytes.isEmpty()) {
                    "\"\""
                } else {
                    "#" + bytes.toHex()
                }
            }
            is ASN1TaggedObject ->
                "[TAG ${primitive.tagNo}]${formatAsn1Primitive(primitive.baseObject)}"
            is ASN1Sequence ->
                primitive.map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "[", postfix = "]", separator = ", ")
            is ASN1Set ->
                primitive.map { formatAsn1Primitive(it) }
                    .joinToString(prefix = "{", postfix = "}", separator = ", ")
            else -> primitive.toString()
        }
    }

    private fun sequenceContainsRootOfTrust(seq: ASN1Encodable): Boolean {
        if (seq !is ASN1Sequence) return false
        return seq.any { element ->
            (element as? ASN1TaggedObject)?.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST
        }
    }

    private fun parseAttestationExtension(certHolder: X509CertificateHolder): ParsedAttestation? {
        val extension = certHolder.getExtension(ATTESTATION_OID) ?: return null
        val sequence = ASN1Sequence.getInstance(extension.extnValue.octets)
        val allFields = sequence.toArray()

        val softwareEnforcedCandidate =
            allFields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX]
        val teeEnforcedCandidate =
            allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX]
        if (
            sequenceContainsRootOfTrust(softwareEnforcedCandidate) &&
                !sequenceContainsRootOfTrust(teeEnforcedCandidate)
        ) {
            allFields[AttestationConstants.KEY_DESCRIPTION_SOFTWARE_ENFORCED_INDEX] =
                teeEnforcedCandidate
            allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX] =
                softwareEnforcedCandidate
        }

        val teeEnforced =
            allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX] as ASN1Sequence

        var originalRootOfTrust: ASN1Encodable? = null
        val teeEnforcedMap = mutableMapOf<Int, ASN1TaggedObject>()

        teeEnforced.forEach { element ->
            val taggedObject = element as ASN1TaggedObject
            if (taggedObject.tagNo == AttestationConstants.TAG_ROOT_OF_TRUST) {
                originalRootOfTrust = taggedObject.baseObject.toASN1Primitive()
            } else {
                teeEnforcedMap[taggedObject.tagNo] = taggedObject
            }
        }
        return ParsedAttestation(allFields, teeEnforcedMap, originalRootOfTrust)
    }

    private fun createPatchedAttestationExtension(parsed: ParsedAttestation, uid: Int): Extension {
        val (allFields, teeEnforcedMap, originalRootOfTrust) = parsed

        SystemLogger.verbose {
            val formattedString = allFields.joinToString(separator = ", ") { formatAsn1Primitive(it) }
            "Original attestation data: $formattedString"
        }

        val newRootOfTrust = AttestationBuilder.buildRootOfTrust(originalRootOfTrust)
        teeEnforcedMap[AttestationConstants.TAG_ROOT_OF_TRUST] =
            DERTaggedObject(true, AttestationConstants.TAG_ROOT_OF_TRUST, newRootOfTrust)

        val simulatedProperties = AttestationBuilder.getSimulatedHardwareProperties(uid)

        simulatedProperties.forEach { (tag, value) ->
            if (value != null) {
                teeEnforcedMap[tag] = value
            } else {
                teeEnforcedMap.remove(tag)
            }
        }

        val sortedElements = teeEnforcedMap.values.sortedBy { it.tagNo }
        val sortedTeeEnforced = DERSequence(sortedElements.toTypedArray())

        allFields[AttestationConstants.KEY_DESCRIPTION_TEE_ENFORCED_INDEX] = sortedTeeEnforced
        val patchedSequence = DERSequence(allFields)
        SystemLogger.verbose {
            val formattedString = patchedSequence.joinToString(separator = ", ") { formatAsn1Primitive(it) }
            "Patched  attestation data: $formattedString"
        }
        val patchedOctets = DEROctetString(patchedSequence)

        return Extension(ATTESTATION_OID, false, patchedOctets)
    }

    private data class ParsedAttestation(
        val allFields: Array<ASN1Encodable>,
        val teeEnforcedMap: MutableMap<Int, ASN1TaggedObject>,
        val rootOfTrust: ASN1Encodable?,
    )
}
