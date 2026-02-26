package com.zourzouvillys.httpsig;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

/**
 * Factory for creating signing and verifying keys for each algorithm.
 */
public final class Keys {

    private Keys() {}

    // ---- RSA-PSS ----

    public static SigningKey rsaPSSSigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_PSS_SHA512; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.rsaPssSign(key, data);
            }
        };
    }

    public static VerifyingKey rsaPSSVerifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new VerifyingKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_PSS_SHA512; }
            @Override public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
                return Algorithms.rsaPssVerify(key, data, signature);
            }
        };
    }

    // ---- ECDSA P-256 ----

    public static SigningKey ecdsaP256SigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.ECDSA_P256_SHA256; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.ecdsaSign(key, data);
            }
        };
    }

    public static VerifyingKey ecdsaP256VerifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new VerifyingKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.ECDSA_P256_SHA256; }
            @Override public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
                return Algorithms.ecdsaVerify(key, data, signature);
            }
        };
    }

    // ---- Ed25519 ----

    public static SigningKey ed25519SigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.ED25519; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.ed25519Sign(key, data);
            }
        };
    }

    public static VerifyingKey ed25519VerifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new VerifyingKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.ED25519; }
            @Override public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
                return Algorithms.ed25519Verify(key, data, signature);
            }
        };
    }

    // ---- HMAC-SHA256 ----

    /**
     * HMAC is symmetric, so the returned object implements both
     * {@link SigningKey} and {@link VerifyingKey}.
     */
    public static HmacKey hmacSHA256Key(String keyId, byte[] secret) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(secret);
        byte[] copy = secret.clone();
        return new HmacKey(keyId, copy);
    }

    /**
     * Symmetric HMAC key that can both sign and verify.
     */
    public static final class HmacKey implements SigningKey, VerifyingKey {
        private final String keyId;
        private final byte[] secret;

        private HmacKey(String keyId, byte[] secret) {
            this.keyId = keyId;
            this.secret = secret;
        }

        @Override public String keyId() { return keyId; }
        @Override public Algorithm algorithm() { return Algorithm.HMAC_SHA256; }

        @Override
        public byte[] sign(byte[] data) throws HttpSigException {
            return Algorithms.hmacSign(secret, data);
        }

        @Override
        public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
            return Algorithms.hmacVerify(secret, data, signature);
        }
    }
}
