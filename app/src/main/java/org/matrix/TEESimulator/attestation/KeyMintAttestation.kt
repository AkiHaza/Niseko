package org.matrix.TEESimulator.attestation

import android.hardware.security.keymint.*
import android.hardware.security.keymint.KeyOrigin
import java.math.BigInteger
import java.util.Date
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.x500.X500Name
import org.matrix.TEESimulator.logging.KeyMintParameterLogger

data class KeyMintAttestation(
    val keySize: Int,
    val algorithm: Int,
    val ecCurve: Int?,
    val ecCurveName: String,
    val origin: Int?,
    val blockMode: List<Int>,
    val padding: List<Int>,
    val purpose: List<Int>,
    val digest: List<Int>,
    val rsaPublicExponent: BigInteger?,
    val certificateSerial: BigInteger?,
    val certificateSubject: X500Name?,
    val certificateNotBefore: Date?,
    val certificateNotAfter: Date?,
    val attestationChallenge: ByteArray?,
    val brand: ByteArray?,
    val device: ByteArray?,
    val product: ByteArray?,
    val serial: ByteArray?,
    val imei: ByteArray?,
    val meid: ByteArray?,
    val manufacturer: ByteArray?,
    val model: ByteArray?,
    val secondImei: ByteArray?,
    val activeDateTime: Date?,
    val originationExpireDateTime: Date?,
    val usageExpireDateTime: Date?,
    val usageCountLimit: Int?,
    val callerNonce: Boolean?,
    val nonce: ByteArray?,
    val unlockedDeviceRequired: Boolean?,
    val includeUniqueId: Boolean?,
    val rollbackResistance: Boolean?,
    val earlyBootOnly: Boolean?,
    val allowWhileOnBody: Boolean?,
    val trustedUserPresenceRequired: Boolean?,
    val trustedConfirmationRequired: Boolean?,
    val noAuthRequired: Boolean?,
    val maxUsesPerBoot: Int?,
    val maxBootLevel: Int?,
    val minMacLength: Int?,
    val rsaOaepMgfDigest: List<Int>,
) {
    constructor(
        params: Array<KeyParameter>
    ) : this(
        keySize = params.findInteger(Tag.KEY_SIZE) ?: params.deriveKeySizeFromCurve(),
        algorithm = params.findAlgorithm(Tag.ALGORITHM) ?: 0,
        ecCurve = params.findEcCurve(Tag.EC_CURVE),
        ecCurveName = params.deriveEcCurveName(),
        origin = params.findOrigin(Tag.ORIGIN),
        blockMode = params.findAllBlockMode(Tag.BLOCK_MODE),
        padding = params.findAllPaddingMode(Tag.PADDING),
        purpose = params.findAllKeyPurpose(Tag.PURPOSE),
        digest = params.findAllDigests(Tag.DIGEST),
        rsaPublicExponent = params.findLongInteger(Tag.RSA_PUBLIC_EXPONENT),
        certificateSerial = params.findBlob(Tag.CERTIFICATE_SERIAL)?.let { BigInteger(it) },
        certificateSubject =
            params.findBlob(Tag.CERTIFICATE_SUBJECT)?.let { X500Name(X500Principal(it).name) },
        certificateNotBefore = params.findDate(Tag.CERTIFICATE_NOT_BEFORE),
        certificateNotAfter = params.findDate(Tag.CERTIFICATE_NOT_AFTER),
        attestationChallenge = params.findBlob(Tag.ATTESTATION_CHALLENGE),
        brand = params.findBlob(Tag.ATTESTATION_ID_BRAND),
        device = params.findBlob(Tag.ATTESTATION_ID_DEVICE),
        product = params.findBlob(Tag.ATTESTATION_ID_PRODUCT),
        serial = params.findBlob(Tag.ATTESTATION_ID_SERIAL),
        imei = params.findBlob(Tag.ATTESTATION_ID_IMEI),
        meid = params.findBlob(Tag.ATTESTATION_ID_MEID),
        manufacturer = params.findBlob(Tag.ATTESTATION_ID_MANUFACTURER),
        model = params.findBlob(Tag.ATTESTATION_ID_MODEL),
        secondImei = params.findBlob(Tag.ATTESTATION_ID_SECOND_IMEI),
        activeDateTime = params.findDate(Tag.ACTIVE_DATETIME),
        originationExpireDateTime = params.findDate(Tag.ORIGINATION_EXPIRE_DATETIME),
        usageExpireDateTime = params.findDate(Tag.USAGE_EXPIRE_DATETIME),
        usageCountLimit = params.findInteger(Tag.USAGE_COUNT_LIMIT),
        callerNonce = params.findBoolean(Tag.CALLER_NONCE),
        nonce = params.findBlob(Tag.NONCE),
        unlockedDeviceRequired = params.findBoolean(Tag.UNLOCKED_DEVICE_REQUIRED),
        includeUniqueId = params.findBoolean(Tag.INCLUDE_UNIQUE_ID),
        rollbackResistance = params.findBoolean(Tag.ROLLBACK_RESISTANCE),
        earlyBootOnly = params.findBoolean(Tag.EARLY_BOOT_ONLY),
        allowWhileOnBody = params.findBoolean(Tag.ALLOW_WHILE_ON_BODY),
        trustedUserPresenceRequired = params.findBoolean(Tag.TRUSTED_USER_PRESENCE_REQUIRED),
        trustedConfirmationRequired = params.findBoolean(Tag.TRUSTED_CONFIRMATION_REQUIRED),
        noAuthRequired = params.findBoolean(Tag.NO_AUTH_REQUIRED),
        maxUsesPerBoot = params.findInteger(Tag.MAX_USES_PER_BOOT),
        maxBootLevel = params.findInteger(Tag.MAX_BOOT_LEVEL),
        minMacLength = params.findInteger(Tag.MIN_MAC_LENGTH),
        rsaOaepMgfDigest = params.findAllDigests(Tag.RSA_OAEP_MGF_DIGEST),
    ) {
        params.forEach { KeyMintParameterLogger.logParameter(it) }
    }

    fun isAttestKey(): Boolean = purpose.size == 1 && purpose.contains(KeyPurpose.ATTEST_KEY)

    fun isImportKey(): Boolean = origin == KeyOrigin.IMPORTED || origin == KeyOrigin.SECURELY_IMPORTED
}

private fun Array<KeyParameter>.findInteger(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.integer

private fun Array<KeyParameter>.findAlgorithm(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.algorithm

private fun Array<KeyParameter>.findEcCurve(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.ecCurve

private fun Array<KeyParameter>.findOrigin(tag: Int): Int? =
    this.find { it.tag == tag }?.value?.origin

private fun Array<KeyParameter>.findLongInteger(tag: Int): BigInteger? =
    this.find { it.tag == tag }?.value?.longInteger?.toBigInteger()

private fun Array<KeyParameter>.findDate(tag: Int): Date? =
    this.find { it.tag == tag }?.value?.dateTime?.let { Date(it) }

private fun Array<KeyParameter>.findBlob(tag: Int): ByteArray? =
    this.find { it.tag == tag }?.value?.blob

private fun Array<KeyParameter>.findAllBlockMode(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.blockMode }

private fun Array<KeyParameter>.findAllPaddingMode(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.paddingMode }

private fun Array<KeyParameter>.findAllKeyPurpose(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.keyPurpose }

private fun Array<KeyParameter>.findAllDigests(tag: Int): List<Int> =
    this.filter { it.tag == tag }.map { it.value.digest }

private fun Array<KeyParameter>.findBoolean(tag: Int): Boolean? =
    if (this.any { it.tag == tag }) true else null

/**
 * Derives KEY_SIZE from EC_CURVE when the tag is absent.
 * AOSP keymint reference HAL lists both Tag::EcCurve and Tag::KeySize, but callers
 * often omit KEY_SIZE when EC_CURVE is present. Without this, keySize defaults to 0,
 * which is a trivial detection vector.
 */
private fun Array<KeyParameter>.deriveKeySizeFromCurve(): Int {
    val curveId = this.find { it.tag == Tag.EC_CURVE }?.value?.ecCurve ?: return 0
    return when (curveId) {
        EcCurve.P_224 -> 224
        EcCurve.P_256 -> 256
        EcCurve.P_384 -> 384
        EcCurve.P_521 -> 521
        EcCurve.CURVE_25519 -> 256
        else -> 0
    }
}

private fun Array<KeyParameter>.deriveEcCurveName(): String {
    val curveParam = this.find { it.tag == Tag.EC_CURVE }
    if (curveParam != null) {
        val curveId = curveParam.value.ecCurve
        return when (curveId) {
            EcCurve.CURVE_25519 -> "CURVE_25519"
            EcCurve.P_224 -> "secp224r1"
            EcCurve.P_256 -> "secp256r1"
            EcCurve.P_384 -> "secp384r1"
            EcCurve.P_521 -> "secp521r1"
            else -> throw IllegalArgumentException("Unknown EC curve: $curveId")
        }
    }
    val keySize = this.findInteger(Tag.KEY_SIZE) ?: 0
    return when (keySize) {
        224 -> "secp224r1"
        384 -> "secp384r1"
        521 -> "secp521r1"
        else -> "secp256r1"
    }
}
