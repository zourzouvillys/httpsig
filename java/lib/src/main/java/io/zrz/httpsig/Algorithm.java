package io.zrz.httpsig;

/**
 * Signature algorithms defined in RFC 9421.
 */
public enum Algorithm {

    RSA_PSS_SHA512("rsa-pss-sha512"),
    RSA_PSS_SHA256("rsa-pss-sha256"),
    RSA_PSS_SHA384("rsa-pss-sha384"),
    RSA_V1_5_SHA256("rsa-v1_5-sha256"),
    ECDSA_P256_SHA256("ecdsa-p256-sha256"),
    ECDSA_P384_SHA384("ecdsa-p384-sha384"),
    ECDSA_P521_SHA512("ecdsa-p521-sha512"),
    ED25519("ed25519"),
    HMAC_SHA256("hmac-sha256"),
    HMAC_SHA384("hmac-sha384"),
    HMAC_SHA512("hmac-sha512");

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
