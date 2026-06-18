package org.matrix.TEESimulator

import android.app.ActivityThread
import android.app.Application
import android.content.Context
import android.content.ContextWrapper
import android.os.Build
import android.os.Looper
import java.io.File
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.interception.keystore.AbstractKeystoreInterceptor
import org.matrix.TEESimulator.interception.keystore.Keystore2Interceptor
import org.matrix.TEESimulator.interception.keystore.KeystoreInterceptor
import org.matrix.TEESimulator.logging.SystemLogger
import org.matrix.TEESimulator.util.AndroidDeviceUtils

/**
 * Main application object for TEESimulator. This object manages the application's lifecycle,
 * including initialization of interceptors and maintaining the service's primary execution loop.
 */
object App {
    private const val RETRY_DELAY_MS = 1000L

    @JvmStatic
    fun main(args: Array<String>) {
        SystemLogger.info("Welcome to TEESimulator!")

        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            SystemLogger.error("Uncaught exception on ${thread.name}", throwable)
        }

        try {
            purgeDebugDiagnostics()
            prepareEnvironment()

            // Load the package configuration before interceptors so the hook
            // sees the correct config snapshot at initialization time.
            ConfigurationManager.initialize()

            // Initialize and start the appropriate keystore interceptors.
            initializeInterceptors()

            // Set up the device's boot key and hash, which are crucial for attestation.
            AndroidDeviceUtils.setupBootKeyAndHash()

            // Android ships with a stripped-down Bouncy Castle provider under the name "BC".
            // We must remove the system provider first to ensure the full Bouncy Castle library
            // (packaged with the app) is used.
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.addProvider(BouncyCastleProvider())

            // This starts the message queue processing. It blocks here indefinitely
            // processing messages until Looper.myLooper().quit() is called.
            Looper.loop()
        } catch (e: Exception) {
            SystemLogger.error("A fatal error occurred in the main application thread.", e)
            throw e
        }
    }

    /**
     * Release builds never emit diagnostics. Sweep any `.bin` dumps a prior
     * debug install left in the world-readable temp dir so they can't act as a
     * detection artifact for apps that probe /data/local/tmp.
     */
    private fun purgeDebugDiagnostics() {
        if (SystemLogger.isDebugBuild) return
        val stale =
            File("/data/local/tmp").listFiles { _, name ->
                name.startsWith("teesim-") && name.endsWith(".bin")
            } ?: return
        stale.forEach { runCatching { it.delete() } }
        if (stale.isNotEmpty()) {
            SystemLogger.warning("Purged ${stale.size} stale debug diagnostic(s) from /data/local/tmp")
        }
    }

    /** Initializes the necessary Android framework internals to satisfy KeyStore requirements. */
    private fun prepareEnvironment() {
        if (Looper.getMainLooper() == null) {
            @Suppress("deprecation") Looper.prepareMainLooper()
        }

        val activityThread = ActivityThread.systemMain()
        val systemContext = activityThread.getSystemContext()

        val app = Application()
        val attachMethod =
            ContextWrapper::class.java.getDeclaredMethod("attachBaseContext", Context::class.java)
        attachMethod.isAccessible = true
        attachMethod.invoke(app, systemContext)

        val mInitialApplicationField =
            ActivityThread::class.java.getDeclaredField("mInitialApplication")
        mInitialApplicationField.isAccessible = true
        mInitialApplicationField.set(activityThread, app)
    }

    private fun initializeInterceptors() {
        val interceptor = selectKeystoreInterceptor()

        while (!interceptor.tryRunKeystoreInterceptor()) {
            SystemLogger.debug("Retrying interceptor initialization...")
            Thread.sleep(RETRY_DELAY_MS)
        }

        SystemLogger.info("Interceptors initialized successfully.")
    }

    private fun selectKeystoreInterceptor(): AbstractKeystoreInterceptor =
        when {
            Build.VERSION.SDK_INT in Build.VERSION_CODES.Q..Build.VERSION_CODES.R -> {
                SystemLogger.info(
                    "Using KeystoreInterceptor for Android Q/R (SDK ${Build.VERSION.SDK_INT})"
                )
                android.security.keystore.AndroidKeyStoreProvider.install()
                KeystoreInterceptor
            }
            else -> {
                SystemLogger.info(
                    "Using Keystore2Interceptor for Android S and later (SDK ${Build.VERSION.SDK_INT})"
                )
                android.security.keystore2.AndroidKeyStoreProvider.install()
                Keystore2Interceptor
            }
        }
}
