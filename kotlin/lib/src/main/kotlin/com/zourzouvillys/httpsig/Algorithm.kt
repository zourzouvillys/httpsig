package com.zourzouvillys.httpsig

/**
 * Signature algorithms defined in RFC 9421.
 */
sealed class Algorithm(val value: String) {

    data object RsaPssSha512 : Algorithm("rsa-pss-sha512")
    data object EcdsaP256Sha256 : Algorithm("ecdsa-p256-sha256")
    data object Ed25519 : Algorithm("ed25519")
    data object HmacSha256 : Algorithm("hmac-sha256")

    companion object {
        fun fromValue(value: String): Algorithm = when (value) {
            RsaPssSha512.value -> RsaPssSha512
            EcdsaP256Sha256.value -> EcdsaP256Sha256
            Ed25519.value -> Ed25519
            HmacSha256.value -> HmacSha256
            else -> throw IllegalArgumentException("unknown algorithm: $value")
        }
    }

    override fun toString(): String = value
}
