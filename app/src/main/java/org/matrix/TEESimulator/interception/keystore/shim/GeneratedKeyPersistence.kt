package org.matrix.TEESimulator.interception.keystore.shim

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyPair
import java.security.MessageDigest
import java.security.cert.Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import org.matrix.TEESimulator.config.ConfigurationManager.CONFIG_PATH
import org.matrix.TEESimulator.interception.keystore.KeyIdentifier
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.CertificateHelper

data class PersistedKeyData(
    val uid: Int,
    val alias: String,
    val nspace: Long,
    val securityLevel: Int,
    val isAttestationKey: Boolean,
    val algorithm: Int,
    val keySize: Int,
    val ecCurve: Int,
    val purposes: List<Int>,
    val digests: List<Int>,
    val privateKeyBytes: ByteArray,
    val certChainBytes: List<ByteArray>,
    val metadataBytes: ByteArray,
    val symmetricKeyBytes: ByteArray,
    val symmetricAlgorithm: String,
)

object GeneratedKeyPersistence {
    private const val FORMAT_VERSION = 3
    private val PERSISTENCE_DIR = File(CONFIG_PATH, "persistent_keys")
    private val fileLocks = ConcurrentHashMap<String, ReentrantLock>()

    private fun getLockForKey(filename: String): ReentrantLock =
        fileLocks.computeIfAbsent(filename) { ReentrantLock() }

    fun save(
        keyId: KeyIdentifier,
        keyPair: KeyPair?,
        secretKey: javax.crypto.SecretKey?,
        nspace: Long,
        securityLevel: Int,
        certChain: List<Certificate>,
        algorithm: Int,
        keySize: Int,
        ecCurve: Int,
        purposes: List<Int>,
        digests: List<Int>,
        isAttestationKey: Boolean,
        metadataBytes: ByteArray? = null,
    ) {
        require(keyPair != null || secretKey != null) {
            "Either keyPair or secretKey must be provided"
        }
        val filename = keyFileName(keyId.uid, keyId.alias)
        val lock = getLockForKey(filename)
        lock.lock()
        try {
            runCatching {
                PERSISTENCE_DIR.mkdirs()
                val finalFile = File(PERSISTENCE_DIR, filename)
                val tmpFile = File(PERSISTENCE_DIR, "$filename.tmp")
                try {
                    DataOutputStream(BufferedOutputStream(FileOutputStream(tmpFile))).use { out ->
                        out.writeInt(FORMAT_VERSION)
                        out.writeInt(securityLevel)
                        out.writeInt(keyId.uid)
                        out.writeUTF(keyId.alias)
                        out.writeLong(nspace)
                        out.writeBoolean(isAttestationKey)
                        out.writeInt(algorithm)
                        out.writeInt(keySize)
                        out.writeInt(ecCurve)
                        out.writeInt(purposes.size)
                        purposes.forEach { out.writeInt(it) }
                        out.writeInt(digests.size)
                        digests.forEach { out.writeInt(it) }
                        val pkBytes = keyPair?.private?.encoded ?: ByteArray(0)
                        out.writeInt(pkBytes.size)
                        out.write(pkBytes)
                        out.writeInt(certChain.size)
                        certChain.forEach { cert ->
                            val encoded = cert.encoded
                            out.writeInt(encoded.size)
                            out.write(encoded)
                        }
                        val mdBytes = metadataBytes ?: ByteArray(0)
                        out.writeInt(mdBytes.size)
                        if (mdBytes.isNotEmpty()) out.write(mdBytes)
                        if (secretKey != null) {
                            val skBytes = secretKey.encoded
                            out.writeUTF(secretKey.algorithm)
                            out.writeInt(skBytes.size)
                            out.write(skBytes)
                        } else {
                            out.writeUTF("")
                            out.writeInt(0)
                        }
                    }
                } catch (e: Exception) {
                    tmpFile.delete()
                    throw e
                }
                if (!tmpFile.renameTo(finalFile)) {
                    tmpFile.delete()
                    throw IllegalStateException("Failed to atomically rename $tmpFile -> $finalFile")
                }
                if (!finalFile.exists() || finalFile.length() < 20) {
                    throw IOException("File write verification failed - possible disk full")
                }
                SystemLogger.debug("Persisted key: $keyId")
            }.onFailure { e ->
                SystemLogger.error("Failed to persist key $keyId", e)
            }
        } finally {
            lock.unlock()
        }
    }

    fun delete(keyId: KeyIdentifier) {
        runCatching {
            val file = File(PERSISTENCE_DIR, keyFileName(keyId.uid, keyId.alias))
            if (file.exists()) {
                if (file.delete()) {
                    fileLocks.remove(keyFileName(keyId.uid, keyId.alias))
                    SystemLogger.debug("Deleted persisted key: $keyId")
                } else {
                    SystemLogger.warning("Failed to delete persisted key file: ${file.name}")
                }
            }
        }.onFailure { e ->
            SystemLogger.error("Failed to delete persisted key $keyId", e)
        }
    }

    fun deleteAll() {
        runCatching {
            if (!PERSISTENCE_DIR.exists()) return
            val files = PERSISTENCE_DIR.listFiles() ?: return
            var count = 0
            files.forEach { file ->
                if (file.name.endsWith(".bin") || file.name.endsWith(".tmp")) {
                    if (file.delete()) count++
                }
            }
            fileLocks.clear()
            SystemLogger.info("Deleted $count persisted key files")
        }.onFailure { e ->
            SystemLogger.error("Failed to delete all persisted keys", e)
        }
    }

    fun loadAll(securityLevel: Int): List<PersistedKeyData> {
        if (!PERSISTENCE_DIR.exists()) return emptyList()
        val files = PERSISTENCE_DIR.listFiles { _, name -> name.endsWith(".bin") } ?: return emptyList()
        if (files.isEmpty()) return emptyList()
        SystemLogger.info("Found ${files.size} persisted key files to process")
        val result = mutableListOf<PersistedKeyData>()
        for (file in files) {
            runCatching {
                DataInputStream(BufferedInputStream(FileInputStream(file))).use { input ->
                    val version = input.readInt()
                    if (version != FORMAT_VERSION) {
                        SystemLogger.info("Skipping ${file.name}: legacy format version $version.")
                        return@runCatching
                    }
                    val storedSecLevel = input.readInt()
                    val uid = input.readInt()
                    val alias = input.readUTF()
                    val nspace = input.readLong()
                    val isAttestKey = input.readBoolean()
                    val algo = input.readInt()
                    val kSize = input.readInt()
                    val curve = input.readInt()
                    val purposeCount = requireBounds(input.readInt(), 64, "purposeCount")
                    val purposes = (0 until purposeCount).map { input.readInt() }
                    val digestCount = requireBounds(input.readInt(), 64, "digestCount")
                    val digests = (0 until digestCount).map { input.readInt() }
                    val pkLen = requireBounds(input.readInt(), 8192, "pkLen")
                    val pkBytes = ByteArray(pkLen)
                    if (pkLen > 0) input.readFully(pkBytes)
                    val certCount = requireBounds(input.readInt(), 10, "certCount")
                    val certChainBytes = (0 until certCount).map {
                        val certLen = requireBounds(input.readInt(), 65536, "certLen")
                        val certBytes = ByteArray(certLen)
                        input.readFully(certBytes)
                        certBytes
                    }
                    val metaLen = requireBounds(input.readInt(), 256 * 1024, "metaLen")
                    val metadataBytes = ByteArray(metaLen).also { if (metaLen > 0) input.readFully(it) }
                    val skAlgo = input.readUTF()
                    val skLen = requireBounds(input.readInt(), 8192, "skLen")
                    val skBytes = ByteArray(skLen).also { if (skLen > 0) input.readFully(it) }
                    if (storedSecLevel == securityLevel) {
                        result.add(PersistedKeyData(uid, alias, nspace, storedSecLevel, isAttestKey,
                            algo, kSize, curve, purposes, digests, pkBytes, certChainBytes,
                            metadataBytes, skBytes, skAlgo))
                    }
                }
            }.onFailure { e ->
                SystemLogger.warning("Skipping corrupted persisted key file: ${file.name}", e)
            }
        }
        SystemLogger.info("Loaded ${result.size} persisted keys for security level $securityLevel")
        return result
    }

    fun rePersistIfNeeded(callingUid: Int, generatedKeyInfo: KeyMintSecurityLevelInterceptor.GeneratedKeyInfo) {
        val metadata = generatedKeyInfo.response.metadata ?: return
        val secLevel = metadata.keySecurityLevel
        val entry = KeyMintSecurityLevelInterceptor.generatedKeys.entries.find { (id, info) ->
            id.uid == callingUid && info.nspace == generatedKeyInfo.nspace
        } ?: return
        val keyId = entry.key
        val existing = File(PERSISTENCE_DIR, keyFileName(keyId.uid, keyId.alias))
        if (!existing.exists()) return
        val newChain = CertificateHelper.getCertificateChain(metadata) ?: return
        val persisted = runCatching {
            DataInputStream(BufferedInputStream(FileInputStream(existing))).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) return
                readPersistedKeyData(input)
            }
        }.getOrNull() ?: return
        val keyPair = generatedKeyInfo.keyPair
        val secretKey = generatedKeyInfo.secretKey
        if (keyPair == null && secretKey == null) return
        val metadataBytes = runCatching {
            android.os.Parcel.obtain().let { parcel ->
                try { metadata.writeToParcel(parcel, 0); parcel.marshall() } finally { parcel.recycle() }
            }
        }.getOrNull()
        save(keyId, keyPair, secretKey, generatedKeyInfo.nspace, secLevel, newChain.toList(),
            persisted.algorithm, persisted.keySize, persisted.ecCurve, persisted.purposes,
            persisted.digests, persisted.isAttestationKey, metadataBytes)
        SystemLogger.debug("Re-persisted key $keyId with updated cert chain")
    }

    private fun requireBounds(value: Int, max: Int, name: String): Int {
        require(value in 0..max) { "$name out of bounds: $value (max $max)" }
        return value
    }

    private fun keyFileName(uid: Int, alias: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest("$uid:$alias".toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) } + ".bin"
    }

    private fun readPersistedKeyData(input: DataInputStream): PersistedKeyData {
        val secLevel = input.readInt()
        val uid = input.readInt()
        val alias = input.readUTF()
        val nspace = input.readLong()
        val isAttestKey = input.readBoolean()
        val algo = input.readInt()
        val kSize = input.readInt()
        val curve = input.readInt()
        val purposeCount = requireBounds(input.readInt(), 64, "purposeCount")
        val purposes = (0 until purposeCount).map { input.readInt() }
        val digestCount = requireBounds(input.readInt(), 64, "digestCount")
        val digests = (0 until digestCount).map { input.readInt() }
        val pkLen = requireBounds(input.readInt(), 8192, "pkLen")
        val pkBytes = ByteArray(pkLen)
        if (pkLen > 0) input.readFully(pkBytes)
        val certCount = requireBounds(input.readInt(), 10, "certCount")
        val certChainBytes = (0 until certCount).map {
            val certLen = requireBounds(input.readInt(), 65536, "certLen")
            val certBytes = ByteArray(certLen)
            input.readFully(certBytes)
            certBytes
        }
        val metaLen = requireBounds(input.readInt(), 256 * 1024, "metaLen")
        val metadataBytes = ByteArray(metaLen).also { if (metaLen > 0) input.readFully(it) }
        val skAlgo = input.readUTF()
        val skLen = requireBounds(input.readInt(), 8192, "skLen")
        val skBytes = ByteArray(skLen).also { if (skLen > 0) input.readFully(it) }
        return PersistedKeyData(uid, alias, nspace, secLevel, isAttestKey, algo, kSize, curve,
            purposes, digests, pkBytes, certChainBytes, metadataBytes, skBytes, skAlgo)
    }
}
