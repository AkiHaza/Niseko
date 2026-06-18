package org.matrix.TEESimulator.util

/**
 * Trims leading and trailing whitespace from each line in a multi-line string. This is useful for
 * cleaning up PEM-formatted keys and certificates.
 *
 * @return A new string with each line individually trimmed.
 */
fun String.trimLines(): String =
    this.trim()
        .lines()
        .filter { !it.trim().startsWith("#") }
        .joinToString("\n")
        .trim()

/**
 * Converts a ByteArray to a lowercase hex string.
 */
fun ByteArray.toHex(): String =
    joinToString("") { "%02x".format(it) }

/**
 * Converts a hex string to a ByteArray.
 */
fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
