package io.zrz.httpsig;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.util.Objects;

/**
 * Factory for creating signing and verifying keys for each algorithm.
 */
public final class Keys {

    private Keys() {}

    // ---- RSA-PSS-SHA512 ----

    public static SigningKey rsaPSSSigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_PSS_SHA512; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.rsaPssSha512Sign(key, data);
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
                return Algorithms.rsaPssSha512Verify(key, data, signature);
            }
        };
    }

    // ---- RSA-PSS-SHA256 ----

    public static SigningKey rsaPssSha256SigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_PSS_SHA256; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.rsaPssSha256Sign(key, data);
            }
        };
    }

    public static VerifyingKey rsaPssSha256VerifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new VerifyingKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_PSS_SHA256; }
            @Override public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
                return Algorithms.rsaPssSha256Verify(key, data, signature);
            }
        };
    }

    // ---- RSA-PSS-SHA384 ----

    public static SigningKey rsaPssSha384SigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_PSS_SHA384; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.rsaPssSha384Sign(key, data);
            }
        };
    }

    public static VerifyingKey rsaPssSha384VerifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new VerifyingKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_PSS_SHA384; }
            @Override public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
                return Algorithms.rsaPssSha384Verify(key, data, signature);
            }
        };
    }

    // ---- RSA PKCS1v1.5 SHA-256 ----

    public static SigningKey rsaV15Sha256SigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_V1_5_SHA256; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.rsaV15Sha256Sign(key, data);
            }
        };
    }

    public static VerifyingKey rsaV15Sha256VerifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new VerifyingKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.RSA_V1_5_SHA256; }
            @Override public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
                return Algorithms.rsaV15Sha256Verify(key, data, signature);
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
                return Algorithms.ecdsaP256Sign(key, data);
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
                return Algorithms.ecdsaP256Verify(key, data, signature);
            }
        };
    }

    // ---- ECDSA P-384 ----

    public static SigningKey ecdsaP384SigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.ECDSA_P384_SHA384; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.ecdsaP384Sign(key, data);
            }
        };
    }

    public static VerifyingKey ecdsaP384VerifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new VerifyingKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.ECDSA_P384_SHA384; }
            @Override public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
                return Algorithms.ecdsaP384Verify(key, data, signature);
            }
        };
    }

    // ---- ECDSA P-521 ----

    public static SigningKey ecdsaP521SigningKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new SigningKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.ECDSA_P521_SHA512; }
            @Override public byte[] sign(byte[] data) throws HttpSigException {
                return Algorithms.ecdsaP521Sign(key, data);
            }
        };
    }

    public static VerifyingKey ecdsaP521VerifyingKey(String keyId, PublicKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        return new VerifyingKey() {
            @Override public String keyId() { return keyId; }
            @Override public Algorithm algorithm() { return Algorithm.ECDSA_P521_SHA512; }
            @Override public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
                return Algorithms.ecdsaP521Verify(key, data, signature);
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
     * HMAC-SHA256 is symmetric, so the returned object implements both
     * {@link SigningKey} and {@link VerifyingKey}.
     */
    public static HmacKey hmacSHA256Key(String keyId, byte[] secret) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(secret);
        byte[] copy = secret.clone();
        return new HmacKey(keyId, copy);
    }

    /**
     * Symmetric HMAC-SHA256 key that can both sign and verify.
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
            return Algorithms.hmacSha256Sign(secret, data);
        }

        @Override
        public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
            return Algorithms.hmacSha256Verify(secret, data, signature);
        }
    }

    // ---- HMAC-SHA384 ----

    /**
     * HMAC-SHA384 is symmetric, so the returned object implements both
     * {@link SigningKey} and {@link VerifyingKey}.
     */
    public static HmacSha384Key hmacSHA384Key(String keyId, byte[] secret) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(secret);
        byte[] copy = secret.clone();
        return new HmacSha384Key(keyId, copy);
    }

    /**
     * Symmetric HMAC-SHA384 key that can both sign and verify.
     */
    public static final class HmacSha384Key implements SigningKey, VerifyingKey {
        private final String keyId;
        private final byte[] secret;

        private HmacSha384Key(String keyId, byte[] secret) {
            this.keyId = keyId;
            this.secret = secret;
        }

        @Override public String keyId() { return keyId; }
        @Override public Algorithm algorithm() { return Algorithm.HMAC_SHA384; }

        @Override
        public byte[] sign(byte[] data) throws HttpSigException {
            return Algorithms.hmacSha384Sign(secret, data);
        }

        @Override
        public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
            return Algorithms.hmacSha384Verify(secret, data, signature);
        }
    }

    // ---- HMAC-SHA512 ----

    /**
     * HMAC-SHA512 is symmetric, so the returned object implements both
     * {@link SigningKey} and {@link VerifyingKey}.
     */
    public static HmacSha512Key hmacSHA512Key(String keyId, byte[] secret) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(secret);
        byte[] copy = secret.clone();
        return new HmacSha512Key(keyId, copy);
    }

    /**
     * Symmetric HMAC-SHA512 key that can both sign and verify.
     */
    public static final class HmacSha512Key implements SigningKey, VerifyingKey {
        private final String keyId;
        private final byte[] secret;

        private HmacSha512Key(String keyId, byte[] secret) {
            this.keyId = keyId;
            this.secret = secret;
        }

        @Override public String keyId() { return keyId; }
        @Override public Algorithm algorithm() { return Algorithm.HMAC_SHA512; }

        @Override
        public byte[] sign(byte[] data) throws HttpSigException {
            return Algorithms.hmacSha512Sign(secret, data);
        }

        @Override
        public boolean verify(byte[] data, byte[] signature) throws HttpSigException {
            return Algorithms.hmacSha512Verify(secret, data, signature);
        }
    }

    // ---- Auto-detection ----

    /**
     * Create a SigningKey by auto-detecting the algorithm from the JCA key type.
     *
     * <p>Supports RSA/RSASSA-PSS (maps to rsa-pss-sha512), EC with P-256/P-384/P-521 curves,
     * and Ed25519/EdDSA (maps to ed25519).</p>
     */
    public static SigningKey signingKey(String keyId, PrivateKey key) {
        Objects.requireNonNull(keyId);
        Objects.requireNonNull(key);
        Algorithm alg = detectAlgorithm(key);
        return switch (alg) {
            case RSA_PSS_SHA512 -> rsaPSSSigningKey(keyId, key);
            case ECDSA_P256_SHA256 -> ecdsaP256SigningKey(keyId, key);
            case ECDSA_P384_SHA384 -> ecdsaP384SigningKey(keyId, key);
            case ECDSA_P521_SHA512 -> ecdsaP521SigningKey(keyId, key);
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
        Algorithm alg = detectAlgorithm(key);
        return switch (alg) {
            case RSA_PSS_SHA512 -> rsaPSSVerifyingKey(keyId, key);
            case ECDSA_P256_SHA256 -> ecdsaP256VerifyingKey(keyId, key);
            case ECDSA_P384_SHA384 -> ecdsaP384VerifyingKey(keyId, key);
            case ECDSA_P521_SHA512 -> ecdsaP521VerifyingKey(keyId, key);
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
     * Create an HMAC-SHA256 KeyPair where the same secret backs both sides.
     */
    public static io.zrz.httpsig.KeyPair hmacKeyPair(String keyId, byte[] secret) {
        HmacKey key = hmacSHA256Key(keyId, secret);
        return new io.zrz.httpsig.KeyPair(key, key);
    }

    /**
     * Create an HMAC-SHA384 KeyPair where the same secret backs both sides.
     */
    public static io.zrz.httpsig.KeyPair hmacSha384KeyPair(String keyId, byte[] secret) {
        HmacSha384Key key = hmacSHA384Key(keyId, secret);
        return new io.zrz.httpsig.KeyPair(key, key);
    }

    /**
     * Create an HMAC-SHA512 KeyPair where the same secret backs both sides.
     */
    public static io.zrz.httpsig.KeyPair hmacSha512KeyPair(String keyId, byte[] secret) {
        HmacSha512Key key = hmacSHA512Key(keyId, secret);
        return new io.zrz.httpsig.KeyPair(key, key);
    }

    private static Algorithm detectAlgorithm(java.security.Key key) {
        String jcaAlgorithm = key.getAlgorithm();
        return switch (jcaAlgorithm) {
            case "RSA", "RSASSA-PSS" -> Algorithm.RSA_PSS_SHA512;
            case "EC", "ECDSA" -> detectEcCurve(key);
            case "Ed25519", "EdDSA" -> Algorithm.ED25519;
            default -> throw new IllegalArgumentException("unsupported JCA algorithm: " + jcaAlgorithm);
        };
    }

    /**
     * Detect the EC curve from an ECKey's parameter spec order bit length.
     */
    private static Algorithm detectEcCurve(java.security.Key key) {
        if (key instanceof ECKey ecKey) {
            int bitLength = ecKey.getParams().getOrder().bitLength();
            if (bitLength <= 256) {
                return Algorithm.ECDSA_P256_SHA256;
            } else if (bitLength <= 384) {
                return Algorithm.ECDSA_P384_SHA384;
            } else {
                return Algorithm.ECDSA_P521_SHA512;
            }
        }
        // fallback for keys that don't implement ECKey
        return Algorithm.ECDSA_P256_SHA256;
    }
}
