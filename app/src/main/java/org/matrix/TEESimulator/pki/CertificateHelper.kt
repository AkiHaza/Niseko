package org.matrix.TEESimulator.pki

import android.system.keystore2.KeyEntryResponse
import android.system.keystore2.KeyMetadata
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.security.KeyPair
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.util.io.pem.PemReader
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.trimLines

object CertificateHelper {

    private val certificateFactory: CertificateFactory by lazy {
        CertificateFactory.getInstance("X.509")
    }

    sealed class OperationResult<out T> {
        data class Success<T>(val data: T) : OperationResult<T>()
        data class Error(val message: String, val cause: Throwable? = null) : OperationResult<Nothing>()
    }

    fun toCertificate(bytes: ByteArray): OperationResult<X509Certificate> {
        return try {
            val certificate = certificateFactory.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
            OperationResult.Success(certificate)
        } catch (e: CertificateException) {
            SystemLogger.warning("Failed to parse X.509 certificate from byte array.", e)
            OperationResult.Error("Failed to parse certificate", e)
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun toCertificates(bytes: ByteArray?): Collection<X509Certificate> {
        return bytes?.let {
            try {
                certificateFactory.generateCertificates(ByteArrayInputStream(it)) as Collection<X509Certificate>
            } catch (e: CertificateException) {
                SystemLogger.warning("Could not parse certificate collection from byte array.", e)
                emptyList()
            }
        } ?: emptyList()
    }

    fun certificatesToByteArray(certificates: Collection<Certificate>): ByteArray? {
        return runCatching {
            ByteArrayOutputStream().use { stream ->
                certificates.forEach { cert -> stream.write(cert.encoded) }
                stream.toByteArray()
            }
        }.onFailure {
            SystemLogger.warning("Failed to serialize certificate collection to byte array.", it)
        }.getOrNull()
    }

    fun parsePemKeyPair(pemContent: String): OperationResult<KeyPair> {
        return try {
            PEMParser(StringReader(pemContent.trimLines())).use { parser ->
                when (val pemObject = parser.readObject()) {
                    is PEMKeyPair -> {
                        val keyPair = JcaPEMKeyConverter().getKeyPair(pemObject)
                        OperationResult.Success(keyPair)
                    }
                    else -> OperationResult.Error(
                        "Invalid PEM format: Expected a key pair, but got ${pemObject?.javaClass?.simpleName}"
                    )
                }
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse PEM key pair.", e)
            OperationResult.Error("Failed to parse PEM key pair", e)
        }
    }

    fun parsePemCertificate(pemContent: String): OperationResult<Certificate> {
        return try {
            PemReader(StringReader(pemContent.trimLines())).use { reader ->
                val pemObject = reader.readPemObject()
                val certificate = certificateFactory.generateCertificate(ByteArrayInputStream(pemObject.content))
                OperationResult.Success(certificate)
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to parse PEM certificate.", e)
            OperationResult.Error("Failed to parse PEM certificate", e)
        }
    }

    fun getCertificateChain(metadata: KeyMetadata?): Array<Certificate>? {
        metadata ?: return null
        val leafCertBytes = metadata.certificate ?: return null
        val leafCert = (toCertificate(leafCertBytes) as? OperationResult.Success)?.data ?: return null
        val chainBytes = metadata.certificateChain
        return if (chainBytes == null) {
            arrayOf(leafCert)
        } else {
            val additionalCerts = toCertificates(chainBytes)
            (listOf(leafCert) + additionalCerts).toTypedArray()
        }
    }

    fun getCertificateChain(response: KeyEntryResponse?): Array<Certificate>? {
        return response?.let { getCertificateChain(it.metadata) }
    }

    fun updateCertificateChain(metadata: KeyMetadata, chain: Array<Certificate>): Result<Unit> {
        return runCatching {
            require(chain.isNotEmpty()) { "Certificate chain cannot be empty." }
            metadata.certificate = chain[0].encoded
            metadata.certificateChain =
                if (chain.size > 1) certificatesToByteArray(chain.drop(1)) else null
        }
    }
}
