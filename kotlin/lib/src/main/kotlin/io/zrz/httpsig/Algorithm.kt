package io.zrz.httpsig

/**
 * Signature algorithms defined in RFC 9421.
 */
sealed class Algorithm(val value: String) {

    data object RsaPssSha512 : Algorithm("rsa-pss-sha512")
    data object RsaPssSha256 : Algorithm("rsa-pss-sha256")
    data object RsaPssSha384 : Algorithm("rsa-pss-sha384")
    data object RsaV15Sha256 : Algorithm("rsa-v1_5-sha256")
    data object EcdsaP256Sha256 : Algorithm("ecdsa-p256-sha256")
    data object EcdsaP384Sha384 : Algorithm("ecdsa-p384-sha384")
    data object EcdsaP521Sha512 : Algorithm("ecdsa-p521-sha512")
    data object Ed25519 : Algorithm("ed25519")
    data object HmacSha256 : Algorithm("hmac-sha256")
    data object HmacSha384 : Algorithm("hmac-sha384")
    data object HmacSha512 : Algorithm("hmac-sha512")

    companion object {
        fun fromValue(value: String): Algorithm = when (value) {
            RsaPssSha512.value -> RsaPssSha512
            RsaPssSha256.value -> RsaPssSha256
            RsaPssSha384.value -> RsaPssSha384
            RsaV15Sha256.value -> RsaV15Sha256
            EcdsaP256Sha256.value -> EcdsaP256Sha256
            EcdsaP384Sha384.value -> EcdsaP384Sha384
            EcdsaP521Sha512.value -> EcdsaP521Sha512
            Ed25519.value -> Ed25519
            HmacSha256.value -> HmacSha256
            HmacSha384.value -> HmacSha384
            HmacSha512.value -> HmacSha512
            else -> throw IllegalArgumentException("unknown algorithm: $value")
        }
    }

    override fun toString(): String = value
}
