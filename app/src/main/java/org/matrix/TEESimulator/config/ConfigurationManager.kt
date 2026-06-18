package org.matrix.TEESimulator.config

import android.content.pm.IPackageManager
import android.os.Build
import android.os.FileObserver
import android.os.IBinder
import android.os.ServiceManager
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.attestation.DeviceAttestationService
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.pki.KeyBoxManager

object ConfigurationManager {

    enum class Mode {
        AUTO,
        PATCH,
        GENERATE,
    }

    const val CONFIG_PATH = "/data/adb/tricky_store"
    private const val TARGET_PACKAGES_FILE = "target.txt"
    private const val PATCH_LEVEL_FILE = "security_patch.txt"
    private const val DEFAULT_KEYBOX_FILE = "keybox.xml"
    private val configRoot = File(CONFIG_PATH)

    @Volatile private var packageModes = mapOf<String, Mode>()
    @Volatile private var packageKeyboxes = mapOf<String, String>()
    @Volatile private var globalCustomPatchLevel: CustomPatchLevel? = null
    @Volatile private var packagePatchLevels = mapOf<String, CustomPatchLevel>()

    private val uidToPackagesCache = ConcurrentHashMap<Int, Array<String>>()

    fun initialize() {
        configRoot.mkdirs()
        SystemLogger.info("Configuration root is: ${configRoot.absolutePath}")

        SystemLogger.info("Waiting for PackageManagerService to be ready...")
        if (getPackageManager() == null) {
            SystemLogger.error("PackageManagerService is not available. TEE check will likely fail.")
        } else {
            SystemLogger.info("PackageManagerService is ready.")
        }

        loadTargetPackages(File(configRoot, TARGET_PACKAGES_FILE))
        loadPatchLevelConfig(File(configRoot, PATCH_LEVEL_FILE))
        ConfigObserver.startWatching()
        SystemLogger.info("Configuration initialized and file observer started.")
    }

    fun getKeyboxFileForUid(uid: Int): String {
        val packages = getPackagesForUid(uid)
        return packages.firstNotNullOfOrNull { pkg -> packageKeyboxes[pkg] } ?: DEFAULT_KEYBOX_FILE
    }

    fun shouldPatch(uid: Int): Boolean {
        val mode = getPackageModeForUid(uid)
        return mode == Mode.PATCH || mode == Mode.AUTO
    }

    fun shouldGenerate(uid: Int): Boolean = getPackageModeForUid(uid) == Mode.GENERATE

    fun shouldSkipUid(uid: Int): Boolean = getPackageModeForUid(uid) == null

    /**
     * Reads the raw package mode without collapsing AUTO to PATCH/GENERATE.
     * Required by dispatch arms that need to distinguish AUTO from explicit modes.
     */
    fun isAutoMode(uid: Int): Boolean {
        for (pkg in getPackagesForUid(uid)) {
            when (packageModes[pkg]) {
                Mode.GENERATE, Mode.PATCH -> return false
                Mode.AUTO -> return true
                null -> continue
            }
        }
        return false
    }

    private fun getPackageModeForUid(uid: Int): Mode? {
        val packages = getPackagesForUid(uid)
        if (packages.isEmpty()) return null

        for (pkg in packages) {
            when (packageModes[pkg]) {
                Mode.GENERATE -> return Mode.GENERATE
                Mode.PATCH -> return Mode.PATCH
                Mode.AUTO -> return if (DeviceAttestationService.isTeeFunctional) Mode.PATCH else Mode.GENERATE
                null -> continue
            }
        }
        return null
    }

    fun getPatchLevelForUid(uid: Int): CustomPatchLevel? {
        val packages = getPackagesForUid(uid)
        val packageSpecificPatchLevel =
            packages.firstNotNullOfOrNull { pkg -> packagePatchLevels[pkg] }
        return packageSpecificPatchLevel ?: globalCustomPatchLevel
    }

    private fun loadTargetPackages(file: File) {
        if (!file.exists()) {
            SystemLogger.warning("Configuration file not found: ${file.absolutePath}")
            return
        }

        val newModes = mutableMapOf<String, Mode>()
        val newKeyboxes = mutableMapOf<String, String>()
        var currentKeybox = DEFAULT_KEYBOX_FILE
        val keyboxRegex = Regex("^\\[([a-zA-Z0-9_.-]+\\.xml)]$")

        try {
            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                keyboxRegex.find(trimmedLine)?.let {
                    currentKeybox = it.groupValues[1]
                    SystemLogger.info("Switching to keybox context: $currentKeybox")
                    return@forEach
                }

                when {
                    trimmedLine.endsWith("!") -> {
                        val pkg = trimmedLine.removeSuffix("!").trim()
                        newModes[pkg] = Mode.GENERATE
                        newKeyboxes[pkg] = currentKeybox
                    }
                    trimmedLine.endsWith("?") -> {
                        val pkg = trimmedLine.removeSuffix("?").trim()
                        newModes[pkg] = Mode.PATCH
                        newKeyboxes[pkg] = currentKeybox
                    }
                    else -> {
                        newModes[trimmedLine] = Mode.AUTO
                        newKeyboxes[trimmedLine] = currentKeybox
                    }
                }
            }

            packageModes = newModes
            packageKeyboxes = newKeyboxes
            uidToPackagesCache.clear()
            SystemLogger.info("Successfully loaded ${newModes.size} package configurations.")
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    private fun loadPatchLevelConfig(file: File) {
        if (!file.exists()) {
            globalCustomPatchLevel = null
            packagePatchLevels = emptyMap()
            return
        }

        try {
            val newPackageLevels = mutableMapOf<String, CustomPatchLevel>()
            var currentContext = ""
            val contextLines = mutableMapOf<String, MutableList<String>>()
            val contextRegex = Regex("^\\[([a-zA-Z0-9_.-]+)]$")

            file.readLines().forEach { line ->
                val trimmedLine = line.trim()
                if (trimmedLine.isEmpty() || trimmedLine.startsWith("#")) return@forEach

                contextRegex.find(trimmedLine)?.let { currentContext = it.groupValues[1] }
                    ?: run {
                        contextLines.computeIfAbsent(currentContext) { mutableListOf() }.add(trimmedLine)
                    }
            }

            fun parseLines(lines: List<String>?): CustomPatchLevel? {
                if (lines.isNullOrEmpty()) return null
                if (lines.size == 1 && '=' !in lines[0]) {
                    return CustomPatchLevel(system = null, vendor = null, boot = null, all = lines[0])
                }
                val map = lines.mapNotNull {
                    val parts = it.split('=', limit = 2)
                    if (parts.size == 2) parts[0].trim().lowercase() to parts[1].trim() else null
                }.toMap()
                val all = map["all"]
                return CustomPatchLevel(
                    system = map["system"] ?: all,
                    vendor = map["vendor"] ?: all,
                    boot = map["boot"] ?: all,
                    all = all,
                )
            }

            var newGlobalLevel = parseLines(contextLines[""])
            // system=prop: force boot/vendor through the same path to prevent
            // cross-component date mismatches on non-Pixel devices.
            if (newGlobalLevel?.system.equals("prop", ignoreCase = true)) {
                SystemLogger.info("system=prop: forcing boot/vendor to derive from device props")
                newGlobalLevel = newGlobalLevel?.copy(boot = "prop", vendor = "prop")
            }
            contextLines.remove("")

            for ((pkg, lines) in contextLines) {
                parseLines(lines)?.let { newPackageLevels[pkg] = it }
            }

            globalCustomPatchLevel = newGlobalLevel
            packagePatchLevels = newPackageLevels
            SystemLogger.info(
                "Loaded custom security patch levels: global config exists=${newGlobalLevel != null}, " +
                    "${newPackageLevels.size} package-specific configs."
            )
        } catch (e: Exception) {
            SystemLogger.error("Failed to load or parse ${file.name}", e)
        }
    }

    private object ConfigObserver : FileObserver(configRoot, CLOSE_WRITE or MOVED_TO or DELETE) {
        override fun onEvent(event: Int, path: String?) {
            path ?: return
            SystemLogger.info("Configuration file change detected: $path (event: $event)")

            val file = if (event != DELETE) File(configRoot, path) else null
            when (path) {
                TARGET_PACKAGES_FILE -> file?.let { loadTargetPackages(it) }
                    ?: SystemLogger.warning("$TARGET_PACKAGES_FILE was deleted.")
                PATCH_LEVEL_FILE -> file?.let { loadPatchLevelConfig(it) }
                    ?: SystemLogger.warning("$PATCH_LEVEL_FILE was deleted.")
                else ->
                    if (path.endsWith(".xml")) {
                        SystemLogger.info("Keybox file $path may have changed. It will be reloaded on next access.")
                        KeyBoxManager.invalidateCache(path)
                        if (Build.VERSION.SDK_INT > Build.VERSION_CODES.R) {
                            // Drop only the patched cert chains so the next attestation request
                            // re-signs with the new keybox. Do NOT drop generatedKeys — that would
                            // destroy every alias/private key in memory and on disk, logging users
                            // out of any app that pinned a persisted keystore alias.
                            org.matrix.TEESimulator.interception.keystore.shim
                                .KeyMintSecurityLevelInterceptor
                                .invalidatePatchedChains("updating $file")
                        }
                    }
            }
        }
    }

    // --- System Service Utilities ---

    private var iPackageManager: IPackageManager? = null
    private val pmDeathRecipient = object : IBinder.DeathRecipient {
        override fun binderDied() {
            (iPackageManager as? IBinder)?.unlinkToDeath(this, 0)
            iPackageManager = null
            SystemLogger.warning("Package manager service died. Will try to reconnect.")
        }
    }

    fun getPackageManager(): IPackageManager? {
        if (iPackageManager == null) {
            val binder = waitForSystemService("package") ?: return null
            binder.linkToDeath(pmDeathRecipient, 0)
            iPackageManager = IPackageManager.Stub.asInterface(binder)
        }
        return iPackageManager
    }

    /**
     * Checks whether the calling PID's SELinux context holds [perm] in [tclass]
     * against our own context. Used for gen_unique_id gate on INCLUDE_UNIQUE_ID.
     */
    fun checkSELinuxPermission(callingPid: Int, tclass: String, perm: String): Boolean {
        return try {
            val callerCtx =
                java.io.File("/proc/$callingPid/attr/current").readText().trim('\u0000', ' ', '\n')
            val selfCtx =
                java.io.File("/proc/self/attr/current").readText().trim('\u0000', ' ', '\n')
            android.os.SELinux.checkSELinuxAccess(callerCtx, selfCtx, tclass, perm)
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Checks whether the calling UID holds [permission] via PackageManager.
     * Used for REQUEST_UNIQUE_ID_ATTESTATION and READ_PRIVILEGED_PHONE_STATE.
     */
    fun hasPermissionForUid(uid: Int, permission: String): Boolean {
        val userId = uid / 100000
        return getPackagesForUid(uid).any { pkg ->
            try {
                getPackageManager()?.checkPermission(permission, pkg, userId) == 0
            } catch (_: Exception) {
                false
            }
        }
    }

    fun getPackagesForUid(uid: Int): Array<String> {
        return uidToPackagesCache.getOrPut(uid) {
            try {
                getPackageManager()?.getPackagesForUid(uid) ?: emptyArray()
            } catch (e: Exception) {
                SystemLogger.warning("Failed to get packages for UID $uid", e)
                emptyArray()
            }
        }
    }

    private fun waitForSystemService(name: String): IBinder? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return ServiceManager.waitForService(name)
        }
        repeat(70) {
            val service = ServiceManager.getService(name)
            if (service != null) return service
            Thread.sleep(500)
        }
        SystemLogger.error("Failed to get system service after multiple retries: $name")
        return null
    }
}

data class CustomPatchLevel(
    val system: String?,
    val vendor: String?,
    val boot: String?,
    val all: String?,
)
