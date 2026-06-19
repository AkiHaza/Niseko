package org.matrix.TEESimulator.interception.keystore

import android.os.IBinder
import android.os.ServiceManager
import kotlin.system.exitProcess
import org.matrix.TEESimulator.interception.core.BinderInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

abstract class AbstractKeystoreInterceptor : BinderInterceptor() {

    protected abstract val serviceName: String
    protected abstract val processName: String
    protected abstract val injectionCommand: String

    protected lateinit var keystoreService: IBinder
    private var injectionAttempted = false
    private var retryCount = 0
    private val maxRetries = 5

    protected open val interceptedCodes: IntArray = intArrayOf()

    fun tryRunKeystoreInterceptor(): Boolean {
        SystemLogger.info("Initializing interceptor for '$serviceName' (attempt ${retryCount + 1})...")
        val service = ServiceManager.getService(serviceName)
        if (service == null) {
            SystemLogger.warning("Service '$serviceName' not found. Will retry.")
            retryCount++
            return false
        }
        val backdoor = getBackdoor(service)
        return if (backdoor != null) {
            setupInterceptor(service, backdoor)
            true
        } else {
            handleMissingBackdoor()
            false
        }
    }

    private fun setupInterceptor(service: IBinder, backdoor: IBinder) {
        keystoreService = service
        SystemLogger.info("Registering interceptor for service: $serviceName")
        register(backdoor, service, this, interceptedCodes)
        service.linkToDeath(createDeathRecipient(), 0)
        onInterceptorReady(service, backdoor)
    }

    private fun handleMissingBackdoor() {
        if (!injectionAttempted) {
            SystemLogger.warning("Backdoor not found. Attempting to inject native library into '$processName'.")
            performInjection()
            injectionAttempted = true
        }
        retryCount++
        if (retryCount >= maxRetries) {
            SystemLogger.error("Failed to find backdoor after $maxRetries retries. Exiting.")
            exitProcess(1)
        }
    }

    private fun performInjection() {
        try {
            val command = arrayOf("/system/bin/sh", "-c", injectionCommand)
            SystemLogger.debug("Executing injection command: ${command.joinToString(" ")}")
            val process = Runtime.getRuntime().exec(command)
            val exitCode = process.waitFor()
            if (exitCode != 0) {
                SystemLogger.error("Injection process failed with exit code $exitCode. Exiting.")
                exitProcess(1)
            }
            SystemLogger.info("Injection process completed.")
        } catch (e: Exception) {
            SystemLogger.error("An exception occurred during injection. Exiting.", e)
            exitProcess(1)
        }
    }

    private fun createDeathRecipient() =
        IBinder.DeathRecipient {
            SystemLogger.error("The intercepted service '$serviceName' has died. Restarting application.")
            exitProcess(0)
        }

    protected open fun onInterceptorReady(service: IBinder, backdoor: IBinder) {}
}
