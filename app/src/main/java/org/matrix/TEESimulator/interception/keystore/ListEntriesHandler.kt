package org.matrix.TEESimulator.interception.keystore

import android.os.Parcel
import android.system.keystore2.Domain
import android.system.keystore2.IKeystoreService
import android.system.keystore2.KeyDescriptor
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import org.matrix.TEESimulator.interception.keystore.shim.KeyMintSecurityLevelInterceptor
import org.matrix.TEESimulator.logging.SystemLogger

object ListEntriesHandler {

    private const val RESPONSE_SIZE_LIMIT = 358400

    private data class ListEntriesParams(
        val domain: Int,
        val namespace: Long,
        val startPastAlias: String?,
    )

    private val pendingParams = ConcurrentHashMap<Long, ListEntriesParams>()

    private fun estimateSafeAmountToReturn(
        keyDescriptors: Array<KeyDescriptor>,
        responseSizeLimit: Int,
    ): Int {
        var itemsToReturn = 0
        var returnedBytes = 0
        for (kd in keyDescriptors) {
            returnedBytes += 4 + 8
            kd.alias?.let { returnedBytes += 4 + it.toByteArray(Charsets.UTF_8).size }
            kd.blob?.let { returnedBytes += 4 + it.size }
            if (returnedBytes > responseSizeLimit) {
                SystemLogger.warning(
                    "Key descriptors list (${keyDescriptors.size} items) may exceed binder size limit, returning $itemsToReturn items with estimated size: $returnedBytes bytes."
                )
                break
            }
            itemsToReturn++
        }
        return itemsToReturn
    }

    fun cacheParameters(txId: Long, data: Parcel, isBatchMode: Boolean): Boolean {
        data.enforceInterface(IKeystoreService.DESCRIPTOR)
        val domain = data.readInt()
        val namespace = data.readLong()
        val startPastAlias = if (isBatchMode) data.readString() else null
        if (domain == Domain.APP) {
            pendingParams[txId] = ListEntriesParams(domain, namespace, startPastAlias)
            SystemLogger.debug("[TX_ID: $txId] Cached ${pendingParams[txId]}.")
            return true
        }
        return false
    }

    fun injectGeneratedKeys(txId: Long, callingUid: Int, reply: Parcel): Array<KeyDescriptor> {
        val params =
            pendingParams.remove(txId)
                ?: throw IllegalStateException("No params found for listing entries")
        val keysToInject =
            extractGeneratedKeyDescriptors(callingUid, callingUid.toLong(), params.startPastAlias)
        val originalList = reply.createTypedArray(KeyDescriptor.CREATOR)!!
        val mergedArray = mergeKeyDescriptors(originalList, keysToInject)
        val safeAmountToReturn = estimateSafeAmountToReturn(mergedArray, RESPONSE_SIZE_LIMIT)
        return if (safeAmountToReturn < mergedArray.size) {
            SystemLogger.debug(
                "[TX_ID: $txId] Listing entries is truncated [${mergedArray.size} -> $safeAmountToReturn]."
            )
            mergedArray.copyOfRange(0, safeAmountToReturn)
        } else {
            SystemLogger.debug(
                "[TX_ID: $txId] Listing entries returns ${mergedArray.size} [injected: ${keysToInject.size}] keys."
            )
            mergedArray
        }
    }

    private fun mergeKeyDescriptors(
        hardwareKeys: Array<KeyDescriptor>,
        keysToInject: List<KeyDescriptor>,
    ): Array<KeyDescriptor> {
        val combinedMap = TreeMap<String, KeyDescriptor>()
        hardwareKeys.forEach { key -> key.alias?.let { combinedMap[it] = key } }
        keysToInject.forEach { key -> key.alias?.let { combinedMap[it] = key } }
        return combinedMap.values.toTypedArray()
    }

    private fun extractGeneratedKeyDescriptors(
        uid: Int,
        namespace: Long,
        startPastAlias: String?,
    ): List<KeyDescriptor> {
        return KeyMintSecurityLevelInterceptor.generatedKeys.keys
            .filter { it.uid == uid && (startPastAlias == null || it.alias > startPastAlias) }
            .map { keyId ->
                KeyDescriptor().apply {
                    this.domain = Domain.APP
                    this.nspace = namespace
                    this.alias = keyId.alias
                    this.blob = null
                }
            }
    }
}
