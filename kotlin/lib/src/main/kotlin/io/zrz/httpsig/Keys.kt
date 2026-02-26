package io.zrz.httpsig

import java.security.PrivateKey
import java.security.PublicKey

/**
 * Factory for creating signing and verifying keys for each algorithm.
 */
object Keys {

    // ---- RSA-PSS ----

    fun rsaPSSSigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaPssSha512
            override fun sign(data: ByteArray): ByteArray = Algorithms.rsaPssSign(key, data)
        }

    fun rsaPSSVerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaPssSha512
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.rsaPssVerify(key, data, signature)
        }

    // ---- ECDSA P-256 ----

    fun ecdsaP256SigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.EcdsaP256Sha256
            override fun sign(data: ByteArray): ByteArray = Algorithms.ecdsaSign(key, data)
        }

    fun ecdsaP256VerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.EcdsaP256Sha256
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.ecdsaVerify(key, data, signature)
        }

    // ---- Ed25519 ----

    fun ed25519SigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.Ed25519
            override fun sign(data: ByteArray): ByteArray = Algorithms.ed25519Sign(key, data)
        }

    fun ed25519VerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.Ed25519
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.ed25519Verify(key, data, signature)
        }

    // ---- HMAC-SHA256 ----

    /**
     * HMAC is symmetric, so the returned object implements both
     * [SigningKey] and [VerifyingKey].
     */
    fun hmacSHA256Key(keyId: String, secret: ByteArray): HmacKey =
        HmacKey(keyId, secret.clone())

    /**
     * Symmetric HMAC key that can both sign and verify.
     */
    class HmacKey internal constructor(
        override val keyId: String,
        private val secret: ByteArray,
    ) : SigningKey, VerifyingKey {

        override val algorithm: Algorithm = Algorithm.HmacSha256

        override fun sign(data: ByteArray): ByteArray = Algorithms.hmacSign(secret, data)

        override fun verify(data: ByteArray, signature: ByteArray): Boolean =
            Algorithms.hmacVerify(secret, data, signature)
    }
}
