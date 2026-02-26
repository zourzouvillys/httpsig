package io.zrz.httpsig

/**
 * A key that can produce signatures.
 */
interface SigningKey {
    val keyId: String
    val algorithm: Algorithm
    fun sign(data: ByteArray): ByteArray
}
