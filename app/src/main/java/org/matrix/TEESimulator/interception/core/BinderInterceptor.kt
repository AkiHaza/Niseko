package org.matrix.TEESimulator.interception.core

import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import org.matrix.TEESimulator.config.ConfigurationManager
import org.matrix.TEESimulator.logging.SystemLogger

abstract class BinderInterceptor : Binder() {

    sealed class TransactionResult {
        object SkipTransaction : TransactionResult()
        object Continue : TransactionResult()
        data class OverrideReply(val reply: Parcel, val code: Int = 0) : TransactionResult()
        data class OverrideData(val data: Parcel) : TransactionResult()
        object ContinueAndSkipPost : TransactionResult()
    }

    open fun onPreTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
    ): TransactionResult = TransactionResult.ContinueAndSkipPost

    open fun onPostTransact(
        txId: Long, target: IBinder, code: Int, flags: Int,
        callingUid: Int, callingPid: Int, data: Parcel,
        reply: Parcel?, resultCode: Int,
    ): TransactionResult = TransactionResult.SkipTransaction

    final override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        val txId = data.readLong()
        val result = try {
            when (code) {
                PRE_TRANSACT_CODE -> handlePreTransact(txId, data)
                POST_TRANSACT_CODE -> handlePostTransact(txId, data)
                else -> return super.onTransact(code, data, reply, flags)
            }
        } catch (e: Throwable) {
            SystemLogger.error("[TX_ID: $txId] Interceptor exception, falling through to HAL", e)
            TransactionResult.ContinueAndSkipPost
        }
        writeResultToReply(result, reply!!)
        return true
    }

    private fun handlePreTransact(txId: Long, data: Parcel): TransactionResult {
        val target = data.readStrongBinder()!!
        val transactionCode = data.readInt()
        val transactionFlags = data.readInt()
        val callingUid = data.readInt()
        val callingPid = data.readInt()
        val dataSize = data.readLong()
        val transactionData = Parcel.obtain()
        return try {
            transactionData.appendFrom(data, data.dataPosition(), dataSize.toInt())
            transactionData.setDataPosition(0)
            onPreTransact(txId, target, transactionCode, transactionFlags, callingUid, callingPid, transactionData)
        } finally { transactionData.recycle() }
    }

    private fun handlePostTransact(txId: Long, data: Parcel): TransactionResult {
        val target = data.readStrongBinder()!!
        val transactionCode = data.readInt()
        val transactionFlags = data.readInt()
        val callingUid = data.readInt()
        val callingPid = data.readInt()
        val transactionData = Parcel.obtain()
        val transactionReply = Parcel.obtain()
        return try {
            val dataSize = data.readLong().toInt()
            transactionData.appendFrom(data, data.dataPosition(), dataSize)
            transactionData.setDataPosition(0)
            data.setDataPosition(data.dataPosition() + dataSize)
            val resultCode = data.readInt()
            val replySize = data.readLong().toInt()
            val reply = if (replySize > 0) {
                transactionReply.appendFrom(data, data.dataPosition(), replySize)
                transactionReply.setDataPosition(0)
                transactionReply
            } else null
            onPostTransact(txId, target, transactionCode, transactionFlags, callingUid, callingPid, transactionData, reply, resultCode)
        } finally { transactionData.recycle(); transactionReply.recycle() }
    }

    private fun writeResultToReply(result: TransactionResult, reply: Parcel) {
        when (result) {
            is TransactionResult.SkipTransaction -> reply.writeInt(RESULT_SKIP_TRANSACTION)
            is TransactionResult.Continue -> reply.writeInt(RESULT_CONTINUE)
            is TransactionResult.OverrideReply -> {
                reply.writeInt(RESULT_OVERRIDE_REPLY)
                reply.writeInt(result.code)
                reply.writeLong(result.reply.dataSize().toLong())
                reply.appendFrom(result.reply, 0, result.reply.dataSize())
                result.reply.recycle()
            }
            is TransactionResult.OverrideData -> {
                reply.writeInt(RESULT_OVERRIDE_DATA)
                reply.writeLong(result.data.dataSize().toLong())
                reply.appendFrom(result.data, 0, result.data.dataSize())
                result.data.recycle()
            }
            is TransactionResult.ContinueAndSkipPost -> reply.writeInt(RESULT_CONTINUE_AND_SKIP_POST)
        }
    }

    protected fun logTransaction(txId: Long, methodName: String, callingUid: Int, callingPid: Int, skipPost: Boolean = false) {
        val isIntercepting = !skipPost && !ConfigurationManager.shouldSkipUid(callingUid)
        val action = if (isIntercepting) "Intercept" else "Observe"
        val packages = ConfigurationManager.getPackagesForUid(callingUid).joinToString()
        val message = "[TX_ID: $txId] $action $methodName for packages=[$packages] (uid=$callingUid, pid=$callingPid)"
        if (isIntercepting) SystemLogger.debug(message) else SystemLogger.verbose(message)
    }

    companion object {
        private const val BACKDOOR_TRANSACTION_CODE = 0xdeadbeef.toInt()
        private const val REGISTER_INTERCEPTOR_CODE = 1
        private const val UNREGISTER_INTERCEPTOR_CODE = 2
        private const val PRE_TRANSACT_CODE = 1
        private const val POST_TRANSACT_CODE = 2
        private const val RESULT_SKIP_TRANSACTION = 1
        private const val RESULT_CONTINUE = 2
        private const val RESULT_OVERRIDE_REPLY = 3
        private const val RESULT_OVERRIDE_DATA = 4
        private const val RESULT_CONTINUE_AND_SKIP_POST = 5

        fun getBackdoor(binder: IBinder): IBinder? {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            return try {
                if (binder.transact(BACKDOOR_TRANSACTION_CODE, data, reply, 0)) {
                    SystemLogger.debug("Backdoor access granted for binder: $binder")
                    reply.readStrongBinder()
                } else null
            } catch (e: Exception) { SystemLogger.error("Failed to transact for backdoor.", e); null }
            finally { data.recycle(); reply.recycle() }
        }

        fun register(backdoor: IBinder, target: IBinder, interceptor: BinderInterceptor, filteredCodes: IntArray = intArrayOf()) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeStrongBinder(target)
                data.writeStrongBinder(interceptor)
                data.writeInt(filteredCodes.size)
                for (code in filteredCodes) data.writeInt(code)
                backdoor.transact(REGISTER_INTERCEPTOR_CODE, data, reply, 0)
                SystemLogger.info("Registered interceptor for target: $target (${filteredCodes.size} filtered codes)")
            } catch (e: Exception) { SystemLogger.error("Failed to register binder interceptor.", e) }
            finally { data.recycle(); reply.recycle() }
        }

        fun unregister(backdoor: IBinder, target: IBinder) {
            val data = Parcel.obtain()
            val reply = Parcel.obtain()
            try {
                data.writeStrongBinder(target)
                backdoor.transact(UNREGISTER_INTERCEPTOR_CODE, data, reply, 0)
                SystemLogger.info("Unregistered interceptor for target: $target")
            } catch (e: Exception) { SystemLogger.error("Failed to unregister binder interceptor.", e) }
            finally { data.recycle(); reply.recycle() }
        }
    }
}
