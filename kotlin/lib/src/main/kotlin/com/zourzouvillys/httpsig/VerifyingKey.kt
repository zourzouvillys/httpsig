package com.zourzouvillys.httpsig

/**
 * A key that can verify signatures.
 */
interface VerifyingKey {
    val keyId: String
    val algorithm: Algorithm
    fun verify(data: ByteArray, signature: ByteArray): Boolean
}
