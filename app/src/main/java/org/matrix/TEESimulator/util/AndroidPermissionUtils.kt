package org.matrix.TEESimulator.util

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import org.matrix.TEESimulator.logging.SystemLogger

/**
 * Utility object for checking Android runtime and SELinux permissions by UID.
 * Uses reflection to obtain the global Application context from ActivityThread,
 * which is necessary because the TEESimulator daemon runs via app_process
 * and does not have a normal Activity-based context.
 */
object AndroidPermissionUtils {

    @SuppressLint("PrivateApi", "DiscouragedPrivateApi")
    private fun getGlobalContext(): Context? {
        return try {
            val activityThreadClass = Class.forName("android.app.ActivityThread")

            val currentActivityThreadMethod = activityThreadClass.getDeclaredMethod("currentActivityThread")
            currentActivityThreadMethod.isAccessible = true
            val activityThread = currentActivityThreadMethod.invoke(null)

            if (activityThread == null) {
                SystemLogger.warning("Reflection: ActivityThread.currentActivityThread() returned null")
                return null
            }

            val getApplicationMethod = activityThreadClass.getDeclaredMethod("getApplication")
            getApplicationMethod.isAccessible = true
            val application = getApplicationMethod.invoke(activityThread) as? Context

            if (application != null) return application

            val getSystemContextMethod = activityThreadClass.getDeclaredMethod("getSystemContext")
            getSystemContextMethod.isAccessible = true
            getSystemContextMethod.invoke(activityThread) as? Context
        } catch (e: Exception) {
            SystemLogger.error("Reflection failed to get global context for permission check", e)
            null
        }
    }

    /**
     * Core permission check.
     * @param uid The UID to check the permission for.
     * @param permission The Android permission string.
     * @return true if the permission is granted.
     */
    fun hasPermission(uid: Int, permission: String): Boolean {
        val context = getGlobalContext() ?: run {
            SystemLogger.warning("AndroidPermissionUtils: Context is null, failing permission check safely.")
            return false
        }

        val result = context.checkPermission(permission, -1, uid)
        return result == PackageManager.PERMISSION_GRANTED
    }

    fun hasDeviceAttestationPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.READ_PRIVILEGED_PHONE_STATE")
    }

    fun hasUniqueIdAttestationPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.REQUEST_UNIQUE_ID_ATTESTATION")
    }

    fun hasManageUsersPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.MANAGE_USERS")
    }

    fun hasDumpPermission(uid: Int): Boolean {
        return hasPermission(uid, "android.permission.DUMP")
    }
}
