package io.zrz.httpsig;

import java.util.Objects;

/**
 * Bundles a {@link SigningKey} and {@link VerifyingKey} that share the same key ID and algorithm.
 */
public record KeyPair(SigningKey signingKey, VerifyingKey verifyingKey) {

    public KeyPair {
        Objects.requireNonNull(signingKey);
        Objects.requireNonNull(verifyingKey);
        if (!signingKey.keyId().equals(verifyingKey.keyId())) {
            throw new IllegalArgumentException("signing and verifying key IDs must match");
        }
        if (signingKey.algorithm() != verifyingKey.algorithm()) {
            throw new IllegalArgumentException("signing and verifying algorithms must match");
        }
    }

    /** The key ID shared by both halves. */
    public String keyId() {
        return signingKey.keyId();
    }

    /** The algorithm shared by both halves. */
    public Algorithm algorithm() {
        return signingKey.algorithm();
    }
}
