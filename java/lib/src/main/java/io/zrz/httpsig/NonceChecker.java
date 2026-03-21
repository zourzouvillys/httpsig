package io.zrz.httpsig;

/**
 * Validates that a signature nonce has not been seen before.
 *
 * <p>Implementations typically record the nonce in a cache or database and
 * throw if a duplicate is detected.  The checker is called after the
 * cryptographic signature has been verified, so it will only be invoked
 * for authentic signatures.
 */
@FunctionalInterface
public interface NonceChecker {

    /**
     * Check the nonce from a verified signature.
     *
     * @param nonce     the nonce value from the signature parameters
     * @param keyId     the key ID of the verified signature
     * @param algorithm the algorithm used by the verified signature
     * @throws Exception if the nonce should be rejected (e.g. replay detected)
     */
    void check(String nonce, String keyId, Algorithm algorithm) throws Exception;
}
