package io.zrz.httpsig

/**
 * Bundles a [SigningKey] and [VerifyingKey] that share the same key ID and algorithm.
 */
data class KeyPair(
    val signingKey: SigningKey,
    val verifyingKey: VerifyingKey,
) {
    init {
        require(signingKey.keyId == verifyingKey.keyId) {
            "signing and verifying key IDs must match"
        }
        require(signingKey.algorithm == verifyingKey.algorithm) {
            "signing and verifying algorithms must match"
        }
    }

    /** The key ID shared by both halves. */
    val keyId: String get() = signingKey.keyId

    /** The algorithm shared by both halves. */
    val algorithm: Algorithm get() = signingKey.algorithm
}
