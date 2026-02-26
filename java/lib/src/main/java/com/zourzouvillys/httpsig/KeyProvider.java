package com.zourzouvillys.httpsig;

/**
 * Resolves a verifying key given a key ID and algorithm hint.
 *
 * Implementations might look up keys in a database, JWKS endpoint, etc.
 */
@FunctionalInterface
public interface KeyProvider {

    /**
     * @return a verifying key, or null if the key is not known/trusted
     */
    VerifyingKey resolve(String keyId, Algorithm algorithm) throws HttpSigException;
}
