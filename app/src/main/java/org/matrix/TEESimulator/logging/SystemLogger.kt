package org.matrix.TEESimulator.logging

import android.util.Log
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import org.matrix.TEESimulator.BuildConfig

object SystemLogger {
    @PublishedApi internal const val TAG = "TEESimulator"

    @PublishedApi internal val isDebugBuild = BuildConfig.DEBUG

    private const val RATE_LIMIT_BURST = 15
    private const val RATE_LIMIT_WINDOW_MS = 1000L
    private val windowStart = AtomicLong(System.currentTimeMillis())
    private val windowCount = AtomicInteger(0)
    private val suppressedCount = AtomicInteger(0)

    @PublishedApi internal fun acquireLogPermit(): Boolean {
        val now = System.currentTimeMillis()
        val start = windowStart.get()
        if (now - start > RATE_LIMIT_WINDOW_MS) {
            if (windowStart.compareAndSet(start, now)) {
                val suppressed = suppressedCount.getAndSet(0)
                windowCount.set(1)
                if (suppressed > 0) {
                    Log.i(TAG, "[rate-limit] suppressed $suppressed log messages in previous window")
                }
                return true
            }
        }
        val count = windowCount.incrementAndGet()
        if (count <= RATE_LIMIT_BURST) return true
        suppressedCount.incrementAndGet()
        return false
    }

    fun debug(message: String) {
        if (!isDebugBuild) return
        if (!acquireLogPermit()) return
        Log.d(TAG, message)
    }

    inline fun debug(message: () -> String) {
        if (!isDebugBuild) return
        if (!acquireLogPermit()) return
        Log.d(TAG, message())
    }

    fun info(message: String) {
        if (!acquireLogPermit()) return
        Log.i(TAG, message)
    }

    inline fun info(message: () -> String) {
        if (!acquireLogPermit()) return
        Log.i(TAG, message())
    }

    fun warning(message: String, throwable: Throwable? = null) {
        if (throwable != null) Log.w(TAG, message, throwable) else Log.w(TAG, message)
    }

    fun error(message: String, throwable: Throwable? = null) {
        if (throwable != null) Log.e(TAG, message, throwable) else Log.e(TAG, message)
    }

    fun verbose(message: String) {
        if (!isDebugBuild) return
        if (!acquireLogPermit()) return
        Log.v(TAG, message)
    }

    inline fun verbose(message: () -> String) {
        if (!isDebugBuild) return
        if (!acquireLogPermit()) return
        Log.v(TAG, message())
    }

    inline fun trace(message: () -> String) {
        if (!isDebugBuild) return
        Log.w(TAG, message())
    }
}
