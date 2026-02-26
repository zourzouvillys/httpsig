package io.zrz.httpsig

/**
 * Resolves a verifying key given a key ID and algorithm hint.
 *
 * Implementations might look up keys in a database, JWKS endpoint, etc.
 */
fun interface KeyProvider {
    /**
     * @return a verifying key, or null if the key is not known/trusted
     */
    fun resolve(keyId: String?, algorithm: Algorithm?): VerifyingKey?
}
