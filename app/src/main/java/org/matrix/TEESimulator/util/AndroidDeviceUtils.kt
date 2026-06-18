package org.matrix.TEESimulator.util

import android.os.Build
import android.os.SystemProperties
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.time.LocalDate
import java.util.concurrent.ThreadLocalRandom
import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.toHex
import org.matrix.TEESimulator.util.hexToBytes

object AndroidDeviceUtils {

    internal const val DO_NOT_REPORT = -1

    val bootKey: ByteArray by lazy {
        initializeBootProperty(
            propertyName = "ro.boot.vbmeta.public_key_digest",
            attestationValueProvider = { DeviceAttestationService.CachedAttestationData?.verifiedBootKey },
            expectedSize = 32,
        )
    }

    val bootHash: ByteArray by lazy {
        initializeBootProperty(
            propertyName = "ro.boot.vbmeta.digest",
            attestationValueProvider = { DeviceAttestationService.CachedAttestationData?.verifiedBootHash },
            expectedSize = 32,
        )
    }

    fun setupBootKeyAndHash() {
        bootKey
        bootHash
    }

    private fun initializeBootProperty(
        propertyName: String,
        attestationValueProvider: () -> ByteArray?,
        expectedSize: Int,
    ): ByteArray {
        getProperty(propertyName, expectedSize)?.let {
            persistToFile(propertyName, it)
            return it
        }
        try {
            attestationValueProvider()?.let {
                setProperty(propertyName, it)
                persistToFile(propertyName, it)
                return it
            }
        } catch (e: Exception) {
            SystemLogger.error("Failed to get $propertyName from attestation.", e)
        }
        readFromFile(propertyName, expectedSize)?.let {
            setProperty(propertyName, it)
            return it
        }
        return generateRandomBytes(expectedSize).also {
            setProperty(propertyName, it)
            persistToFile(propertyName, it)
        }
    }

    @OptIn(ExperimentalStdlibApi::class)
    private fun getProperty(name: String, expectedSize: Int): ByteArray? {
        val value = SystemProperties.get(name, null)
        if (value.isNullOrBlank()) return null
        return if (value.length == expectedSize * 2) value.hexToByteArray() else null
    }

    private fun setProperty(name: String, bytes: ByteArray) {
        val hex = bytes.toHex()
        try {
            val process = Runtime.getRuntime().exec(arrayOf("resetprop", name, hex))
            process.waitFor()
        } catch (e: Exception) {
            SystemLogger.error("Failed to set '$name' property via resetprop.", e)
        }
    }

    /** String overload for setting plain string properties via resetprop. */
    internal fun setProperty(name: String, value: String) {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("resetprop", name, value))
            process.waitFor()
        } catch (e: Exception) {
            SystemLogger.error("Failed to set '$name' property via resetprop.", e)
        }
    }

    private fun generateRandomBytes(size: Int): ByteArray =
        ByteArray(size).also { ThreadLocalRandom.current().nextBytes(it) }

    private val PERSIST_DIR = File("/data/adb/tricky_store")

    private fun fileForProperty(propertyName: String): File = when (propertyName) {
        "ro.boot.vbmeta.digest" -> File(PERSIST_DIR, "boot_hash.bin")
        "ro.boot.vbmeta.public_key_digest" -> File(PERSIST_DIR, "boot_key.bin")
        else -> File(PERSIST_DIR, "${propertyName.replace('.', '_')}.bin")
    }

    private fun persistToFile(propertyName: String, bytes: ByteArray) {
        try { fileForProperty(propertyName).writeBytes(bytes) } catch (e: Exception) {
            SystemLogger.error("Failed to persist $propertyName to file.", e)
        }
    }

    private fun readFromFile(propertyName: String, expectedSize: Int): ByteArray? {
        return try {
            val file = fileForProperty(propertyName)
            if (!file.exists()) return null
            val bytes = file.readBytes()
            if (bytes.size == expectedSize) bytes else null
        } catch (e: Exception) {
            SystemLogger.error("Failed to read $propertyName from file.", e)
            null
        }
    }

    // --- Patch Level Properties ---

    fun getPatchLevel(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "system", isLong = false)
        return custom ?: getRealDevicePatchLevelInt("system", isLong = false)
    }

    fun getVendorPatchLevelLong(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "vendor", isLong = true)
        return custom ?: getRealDevicePatchLevelInt("vendor", isLong = true)
    }

    fun getBootPatchLevelLong(uid: Int): Int {
        val custom = getCustomPatchLevelFor(uid, "boot", isLong = true)
        return custom ?: getRealDevicePatchLevelInt("boot", isLong = true)
    }

    private fun getRealDevicePatchLevelInt(component: String, isLong: Boolean): Int {
        DeviceAttestationService.CachedAttestationData?.let { data ->
            val value = when (component) {
                "system" -> data.osPatchLevel
                "vendor" -> data.vendorPatchLevel
                "boot" -> data.bootPatchLevel
                else -> null
            }
            if (value != null) return value
        }
        if (component == "vendor") {
            val propValue = SystemProperties.get("ro.vendor.build.security_patch", "")
            if (!propValue.isNullOrBlank()) {
                parsePatchLevelValue(propValue, isLong)?.let { return it }
            }
        }
        return Build.VERSION.SECURITY_PATCH.toPatchLevelInt(isLong)
    }

    private fun getCustomPatchLevelFor(uid: Int, component: String, isLong: Boolean): Int? {
        val config = ConfigurationManager.getPatchLevelForUid(uid) ?: return null
        val value = when (component) {
            "system" -> config.system ?: config.all
            "vendor" -> config.vendor ?: config.all
            "boot" -> config.boot ?: config.all
            else -> config.all
        } ?: return null

        val resolvedValue = resolveDateKeywords(value)

        return when {
            resolvedValue.equals("device_default", ignoreCase = true) -> null
            resolvedValue.equals("prop", ignoreCase = true) ->
                parsePatchLevelValue(SystemProperties.get("ro.build.version.security_patch", ""), isLong)
            resolvedValue.equals("no", ignoreCase = true) -> DO_NOT_REPORT
            else -> parsePatchLevelValue(resolvedValue, isLong)
        }
    }

    private fun resolveDateKeywords(value: String): String {
        if (value.equals("today", ignoreCase = true)) return LocalDate.now().toString()
        if (value.contains("YYYY", ignoreCase = true) || value.contains("MM", ignoreCase = true) || value.contains("DD", ignoreCase = true)) {
            val now = LocalDate.now()
            return value
                .replace("YYYY", now.year.toString(), ignoreCase = true)
                .replace("MM", String.format("%02d", now.monthValue), ignoreCase = true)
                .replace("DD", String.format("%02d", now.dayOfMonth), ignoreCase = true)
        }
        return value
    }

    /**
     * Parses a patch level string into an integer.
     * For YYYY-MM input (6 chars), does NOT synthesize day=01 — returns null for
     * isLong=true so callers fall back to a YYYY-MM-DD source. This prevents
     * mismatches with real device bulletin dates on older Samsung firmware.
     */
    private fun parsePatchLevelValue(value: String, isLong: Boolean): Int? {
        val normalized = value.replace("-", "")
        return try {
            when (normalized.length) {
                8 -> {
                    val year = normalized.substring(0, 4).toInt()
                    val month = normalized.substring(4, 6).toInt()
                    val day = normalized.substring(6, 8).toInt()
                    if (isLong) year * 10000 + month * 100 + day else year * 100 + month
                }
                6 -> {
                    val year = normalized.substring(0, 4).toInt()
                    val month = normalized.substring(4, 6).toInt()
                    if (isLong) null else year * 100 + month
                }
                else -> null
            }
        } catch (e: NumberFormatException) {
            SystemLogger.warning("Could not parse patch level value: $value", e)
            null
        }
    }

    private fun String.toPatchLevelInt(isLong: Boolean): Int =
        parsePatchLevelValue(this, isLong) ?: 20240401

    // --- OS and Attestation Version Properties ---

    private val osVersionMap = mapOf(
        Build.VERSION_CODES.BAKLAVA to 160000,
        Build.VERSION_CODES.VANILLA_ICE_CREAM to 150000,
        Build.VERSION_CODES.UPSIDE_DOWN_CAKE to 140000,
        Build.VERSION_CODES.TIRAMISU to 130000,
        Build.VERSION_CODES.S_V2 to 120100,
        Build.VERSION_CODES.S to 120000,
        Build.VERSION_CODES.R to 110000,
        Build.VERSION_CODES.Q to 100000,
    )

    val osVersion: Int
        get() = DeviceAttestationService.CachedAttestationData?.osVersion
            ?: osVersionMap[Build.VERSION.SDK_INT] ?: 160000

    private val attestVersionMap = mapOf(
        Build.VERSION_CODES.Q to 4,
        Build.VERSION_CODES.R to 4,
        Build.VERSION_CODES.S to 100,
        Build.VERSION_CODES.S_V2 to 100,
        Build.VERSION_CODES.TIRAMISU to 200,
        Build.VERSION_CODES.UPSIDE_DOWN_CAKE to 300,
        Build.VERSION_CODES.VANILLA_ICE_CREAM to 300,
        Build.VERSION_CODES.BAKLAVA to 400,
    )

    /**
     * Retrieves the attestation version for the given security level.
     * Uses the same SDK_INT→version map for both TEE and StrongBox — a static
     * StrongBox=300 floor would force a major-version mismatch with the TEE
     * chain on Android 16 devices that report keymaster 400 across both levels.
     */
    fun getAttestVersion(securityLevel: Int): Int {
        val cached = DeviceAttestationService.CachedAttestationData?.attestVersion
        return cached ?: attestVersionMap[Build.VERSION.SDK_INT] ?: 400
    }

    fun getKeymasterVersion(securityLevel: Int): Int = getAttestVersion(securityLevel)

    // --- APEX and Module Hash Properties ---

    private class MinimalApexManifestParser(private val data: ByteArray) {
        var pos = 0
        fun parse(): Pair<String, Long>? {
            var name: String? = null
            var version: Long? = null
            while (pos < data.size) {
                val tag = readVarint()
                val fieldNum = tag ushr 3
                val wireType = (tag and 0x07).toInt()
                when (fieldNum) {
                    1L -> { val length = readVarint().toInt(); if (pos + length > data.size) return null; name = String(data, pos, length, Charsets.UTF_8); pos += length }
                    2L -> { version = readVarint() }
                    else -> skipField(wireType)
                }
            }
            return if (name != null && version != null) name to version else null
        }
        private fun readVarint(): Long {
            var value = 0L; var shift = 0
            while (pos < data.size) { val b = data[pos++].toInt(); value = value or ((b and 0x7F).toLong() shl shift); if ((b and 0x80) == 0) return value; shift += 7 }
            return value
        }
        private fun skipField(wireType: Int) {
            when (wireType) { 0 -> readVarint(); 1 -> pos += 8; 2 -> { val len = readVarint().toInt(); pos += len }; 5 -> pos += 4; else -> throw IllegalStateException("Unknown wire type $wireType") }
        }
    }

    private val apexInfos: List<Pair<String, Long>> by lazy {
        val results = mutableListOf<Pair<String, Long>>()
        val apexRoot = File("/apex")
        if (!apexRoot.exists() || !apexRoot.isDirectory) return@lazy emptyList()
        apexRoot.listFiles()?.forEach { file ->
            if (!file.isDirectory) return@forEach
            val name = file.name
            if (name.startsWith(".") || name.contains("@") || name == "sharedlibs") return@forEach
            val manifestFile = File(file, "apex_manifest.pb")
            if (manifestFile.exists()) {
                runCatching {
                    val bytes = FileInputStream(manifestFile).use { it.readBytes() }
                    MinimalApexManifestParser(bytes).parse()?.let { (pkgName, version) -> results.add(pkgName to version) }
                }
            }
        }
        results.distinctBy { it.first }
    }

    val moduleHash: ByteArray by lazy {
        DeviceAttestationService.CachedAttestationData?.moduleHash
            ?: runCatching {
                data class ModuleEntry(val nameEncoded: ByteArray, val fullEncoded: ByteArray)
                val modules = apexInfos.map { (packageName, versionCode) ->
                    val nameOctet = DEROctetString(packageName.toByteArray(Charsets.UTF_8))
                    val vec = ASN1EncodableVector(); vec.add(nameOctet); vec.add(ASN1Integer(versionCode))
                    val sequence = DERSequence(vec)
                    ModuleEntry(nameEncoded = nameOctet.encoded, fullEncoded = sequence.encoded)
                }
                val sortedModules = modules.sortedWith { m1, m2 -> compareByteArrays(m1.nameEncoded, m2.nameEncoded) }
                val payloadStream = ByteArrayOutputStream()
                sortedModules.forEach { payloadStream.write(it.fullEncoded) }
                val payload = payloadStream.toByteArray()
                val finalDerSet = encodeAsDerSet(payload)
                MessageDigest.getInstance("SHA-256").digest(finalDerSet)
            }.getOrElse {
                SystemLogger.error("Failed to compute module hash.", it)
                ByteArray(32)
            }
    }

    private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
        val length = minOf(a.size, b.size)
        for (i in 0 until length) { val byteA = a[i].toInt() and 0xFF; val byteB = b[i].toInt() and 0xFF; if (byteA != byteB) return byteA - byteB }
        return a.size - b.size
    }

    private fun encodeAsDerSet(payload: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(); out.write(0x31); writeDerLength(out, payload.size); out.write(payload); return out.toByteArray()
    }

    private fun writeDerLength(out: ByteArrayOutputStream, length: Int) {
        if (length < 128) { out.write(length) } else {
            var size = length; val bytes = ArrayList<Byte>()
            while (size > 0) { bytes.add((size and 0xFF).toByte()); size = size ushr 8 }
            out.write(0x80 or bytes.size)
            for (i in bytes.indices.reversed()) out.write(bytes[i].toInt())
        }
    }
}
