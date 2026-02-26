package com.zourzouvillys.httpsig;

/**
 * Signature algorithms defined in RFC 9421.
 */
public enum Algorithm {

    RSA_PSS_SHA512("rsa-pss-sha512"),
    ECDSA_P256_SHA256("ecdsa-p256-sha256"),
    ED25519("ed25519"),
    HMAC_SHA256("hmac-sha256");

    private final String value;

    Algorithm(String value) {
        this.value = value;
    }

    public String value() {
        return value;
    }

    /**
     * Look up an algorithm by its RFC 9421 string identifier.
     *
     * @throws IllegalArgumentException if the value doesn't match any known algorithm
     */
    public static Algorithm fromValue(String value) {
        for (Algorithm alg : values()) {
            if (alg.value.equals(value)) {
                return alg;
            }
        }
        throw new IllegalArgumentException("unknown algorithm: " + value);
    }
}
