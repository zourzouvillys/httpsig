package io.zrz.httpsig;

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

    // ---- Auto-detection ----

    /**
     * Create a SigningKey by auto-detecting the algorithm from the JCA key type.
     *
     * <p>Supports RSA/RSASSA-PSS (maps to rsa-pss-sha512), EC with P-256 curve
     * (maps to ecdsa-p256-sha256), and Ed25519/EdDSA (maps to ed25519).</p>
     */
    public static SigningKey signingKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        Algorithm alg = detectAlgorithm(key.getAlgorithm());
        return switch (alg) {
            case RSA_PSS_SHA512 -> rsaPSSSigningKey(keyId, key);
            case ECDSA_P256_SHA256 -> ecdsaP256SigningKey(keyId, key);
            case ED25519 -> ed25519SigningKey(keyId, key);
            default -> throw new IllegalArgumentException("unsupported key algorithm: " + key.getAlgorithm());
        };
    }

    /**
     * Create a VerifyingKey by auto-detecting the algorithm from the JCA key type.
     */
    public static VerifyingKey verifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        Algorithm alg = detectAlgorithm(key.getAlgorithm());
        return switch (alg) {
            case RSA_PSS_SHA512 -> rsaPSSVerifyingKey(keyId, key);
            case ECDSA_P256_SHA256 -> ecdsaP256VerifyingKey(keyId, key);
            case ED25519 -> ed25519VerifyingKey(keyId, key);
            default -> throw new IllegalArgumentException("unsupported key algorithm: " + key.getAlgorithm());
        };
    }

    /**
     * Create a KeyPair from a JCA {@link java.security.KeyPair}, auto-detecting the algorithm.
     */
    public static io.zrz.httpsig.KeyPair keyPair(String keyId, java.security.KeyPair jcaKeyPair) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(jcaKeyPair);
        return new io.zrz.httpsig.KeyPair(
            signingKey(keyId, jcaKeyPair.getPrivate()),
            verifyingKey(keyId, jcaKeyPair.getPublic())
        );
    }

    /**
     * Create a KeyPair from explicit private and public keys, auto-detecting the algorithm.
     */
    public static io.zrz.httpsig.KeyPair keyPair(String keyId, PrivateKey privateKey, PublicKey publicKey) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(privateKey);
        Objects.requireNonNull(publicKey);
        return new io.zrz.httpsig.KeyPair(
            signingKey(keyId, privateKey),
            verifyingKey(keyId, publicKey)
        );
    }

    /**
     * Create an HMAC KeyPair where the same secret backs both sides.
     */
    public static io.zrz.httpsig.KeyPair hmacKeyPair(String keyId, byte[] secret) {
        HmacKey key = hmacSHA256Key(keyId, secret);
        return new io.zrz.httpsig.KeyPair(key, key);
    }

    private static Algorithm detectAlgorithm(String jcaAlgorithm) {
        return switch (jcaAlgorithm) {
            case "RSA", "RSASSA-PSS" -> Algorithm.RSA_PSS_SHA512;
            case "EC", "ECDSA" -> Algorithm.ECDSA_P256_SHA256;
            case "Ed25519", "EdDSA" -> Algorithm.ED25519;
            default -> throw new IllegalArgumentException("unsupported JCA algorithm: " + jcaAlgorithm);
        };
    }
}
