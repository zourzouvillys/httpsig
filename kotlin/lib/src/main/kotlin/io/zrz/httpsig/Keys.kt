package io.zrz.httpsig

import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECKey

/**
 * Factory for creating signing and verifying keys for each algorithm.
 */
object Keys {

    // ---- RSA-PSS-SHA512 ----

    fun rsaPSSSigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaPssSha512
            override fun sign(data: ByteArray): ByteArray = Algorithms.rsaPssSha512Sign(key, data)
        }

    fun rsaPSSVerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaPssSha512
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.rsaPssSha512Verify(key, data, signature)
        }

    // ---- RSA-PSS-SHA256 ----

    fun rsaPssSha256SigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaPssSha256
            override fun sign(data: ByteArray): ByteArray = Algorithms.rsaPssSha256Sign(key, data)
        }

    fun rsaPssSha256VerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaPssSha256
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.rsaPssSha256Verify(key, data, signature)
        }

    // ---- RSA-PSS-SHA384 ----

    fun rsaPssSha384SigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaPssSha384
            override fun sign(data: ByteArray): ByteArray = Algorithms.rsaPssSha384Sign(key, data)
        }

    fun rsaPssSha384VerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaPssSha384
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.rsaPssSha384Verify(key, data, signature)
        }

    // ---- RSA PKCS1v1.5 SHA-256 ----

    fun rsaV15Sha256SigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaV15Sha256
            override fun sign(data: ByteArray): ByteArray = Algorithms.rsaV15Sha256Sign(key, data)
        }

    fun rsaV15Sha256VerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.RsaV15Sha256
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.rsaV15Sha256Verify(key, data, signature)
        }

    // ---- ECDSA P-256 ----

    fun ecdsaP256SigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.EcdsaP256Sha256
            override fun sign(data: ByteArray): ByteArray = Algorithms.ecdsaP256Sign(key, data)
        }

    fun ecdsaP256VerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.EcdsaP256Sha256
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.ecdsaP256Verify(key, data, signature)
        }

    // ---- ECDSA P-384 ----

    fun ecdsaP384SigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.EcdsaP384Sha384
            override fun sign(data: ByteArray): ByteArray = Algorithms.ecdsaP384Sign(key, data)
        }

    fun ecdsaP384VerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.EcdsaP384Sha384
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.ecdsaP384Verify(key, data, signature)
        }

    // ---- ECDSA P-521 ----

    fun ecdsaP521SigningKey(keyId: String, key: PrivateKey): SigningKey =
        object : SigningKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.EcdsaP521Sha512
            override fun sign(data: ByteArray): ByteArray = Algorithms.ecdsaP521Sign(key, data)
        }

    fun ecdsaP521VerifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        object : VerifyingKey {
            override val keyId: String = keyId
            override val algorithm: Algorithm = Algorithm.EcdsaP521Sha512
            override fun verify(data: ByteArray, signature: ByteArray): Boolean =
                Algorithms.ecdsaP521Verify(key, data, signature)
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
        HmacKey(keyId, secret.clone(), Algorithm.HmacSha256)

    // ---- HMAC-SHA384 ----

    fun hmacSHA384Key(keyId: String, secret: ByteArray): HmacKey =
        HmacKey(keyId, secret.clone(), Algorithm.HmacSha384)

    // ---- HMAC-SHA512 ----

    fun hmacSHA512Key(keyId: String, secret: ByteArray): HmacKey =
        HmacKey(keyId, secret.clone(), Algorithm.HmacSha512)

    /**
     * Symmetric HMAC key that can both sign and verify.
     */
    class HmacKey internal constructor(
        override val keyId: String,
        private val secret: ByteArray,
        override val algorithm: Algorithm,
    ) : SigningKey, VerifyingKey {

        override fun sign(data: ByteArray): ByteArray = when (algorithm) {
            Algorithm.HmacSha256 -> Algorithms.hmacSha256Sign(secret, data)
            Algorithm.HmacSha384 -> Algorithms.hmacSha384Sign(secret, data)
            Algorithm.HmacSha512 -> Algorithms.hmacSha512Sign(secret, data)
            else -> throw IllegalStateException("unexpected HMAC algorithm: $algorithm")
        }

        override fun verify(data: ByteArray, signature: ByteArray): Boolean = when (algorithm) {
            Algorithm.HmacSha256 -> Algorithms.hmacSha256Verify(secret, data, signature)
            Algorithm.HmacSha384 -> Algorithms.hmacSha384Verify(secret, data, signature)
            Algorithm.HmacSha512 -> Algorithms.hmacSha512Verify(secret, data, signature)
            else -> throw IllegalStateException("unexpected HMAC algorithm: $algorithm")
        }
    }

    // ---- Auto-detection ----

    /**
     * Create a [SigningKey] by auto-detecting the algorithm from the JCA key type.
     *
     * For RSA keys, defaults to rsa-pss-sha512. For EC keys, the curve is inspected
     * to select P-256/P-384/P-521 automatically.
     */
    fun signingKey(keyId: String, key: PrivateKey): SigningKey =
        when (val alg = detectAlgorithm(key)) {
            Algorithm.RsaPssSha512 -> rsaPSSSigningKey(keyId, key)
            Algorithm.EcdsaP256Sha256 -> ecdsaP256SigningKey(keyId, key)
            Algorithm.EcdsaP384Sha384 -> ecdsaP384SigningKey(keyId, key)
            Algorithm.EcdsaP521Sha512 -> ecdsaP521SigningKey(keyId, key)
            Algorithm.Ed25519 -> ed25519SigningKey(keyId, key)
            Algorithm.HmacSha256, Algorithm.HmacSha384, Algorithm.HmacSha512 ->
                throw IllegalArgumentException(
                    "HMAC keys are symmetric; use hmacSHA256Key()/hmacSHA384Key()/hmacSHA512Key() instead"
                )
            else -> throw IllegalArgumentException("unsupported key algorithm: ${key.algorithm}")
        }

    /**
     * Create a [VerifyingKey] by auto-detecting the algorithm from the JCA key type.
     */
    fun verifyingKey(keyId: String, key: PublicKey): VerifyingKey =
        when (val alg = detectAlgorithm(key)) {
            Algorithm.RsaPssSha512 -> rsaPSSVerifyingKey(keyId, key)
            Algorithm.EcdsaP256Sha256 -> ecdsaP256VerifyingKey(keyId, key)
            Algorithm.EcdsaP384Sha384 -> ecdsaP384VerifyingKey(keyId, key)
            Algorithm.EcdsaP521Sha512 -> ecdsaP521VerifyingKey(keyId, key)
            Algorithm.Ed25519 -> ed25519VerifyingKey(keyId, key)
            Algorithm.HmacSha256, Algorithm.HmacSha384, Algorithm.HmacSha512 ->
                throw IllegalArgumentException(
                    "HMAC keys are symmetric; use hmacSHA256Key()/hmacSHA384Key()/hmacSHA512Key() instead"
                )
            else -> throw IllegalArgumentException("unsupported key algorithm: ${key.algorithm}")
        }

    /**
     * Create a [KeyPair] from a JCA [java.security.KeyPair], auto-detecting the algorithm.
     */
    fun keyPair(keyId: String, jcaKeyPair: java.security.KeyPair): KeyPair =
        KeyPair(
            signingKey(keyId, jcaKeyPair.private),
            verifyingKey(keyId, jcaKeyPair.public),
        )

    /**
     * Create a [KeyPair] from explicit private and public keys, auto-detecting the algorithm.
     */
    fun keyPair(keyId: String, privateKey: PrivateKey, publicKey: PublicKey): KeyPair =
        KeyPair(
            signingKey(keyId, privateKey),
            verifyingKey(keyId, publicKey),
        )

    /**
     * Create an HMAC [KeyPair] where the same secret backs both sides.
     */
    fun hmacKeyPair(keyId: String, secret: ByteArray): KeyPair {
        val key = hmacSHA256Key(keyId, secret)
        return KeyPair(key, key)
    }

    /**
     * Create an HMAC-SHA384 [KeyPair] where the same secret backs both sides.
     */
    fun hmacSha384KeyPair(keyId: String, secret: ByteArray): KeyPair {
        val key = hmacSHA384Key(keyId, secret)
        return KeyPair(key, key)
    }

    /**
     * Create an HMAC-SHA512 [KeyPair] where the same secret backs both sides.
     */
    fun hmacSha512KeyPair(keyId: String, secret: ByteArray): KeyPair {
        val key = hmacSHA512Key(keyId, secret)
        return KeyPair(key, key)
    }

    /**
     * Detect the algorithm from a JCA key, inspecting curve parameters for EC keys.
     */
    private fun detectAlgorithm(key: java.security.Key): Algorithm {
        val jcaAlgorithm = key.algorithm
        return when (jcaAlgorithm) {
            "RSA", "RSASSA-PSS" -> Algorithm.RsaPssSha512
            "EC", "ECDSA" -> detectEcAlgorithm(key)
            "Ed25519", "EdDSA" -> Algorithm.Ed25519
            else -> throw IllegalArgumentException("unsupported JCA algorithm: $jcaAlgorithm")
        }
    }

    /**
     * Inspect the EC key's curve parameters to select the correct ECDSA algorithm.
     */
    private fun detectEcAlgorithm(key: java.security.Key): Algorithm {
        if (key is ECKey) {
            val bitLength = key.params.order.bitLength()
            return when {
                bitLength <= 256 -> Algorithm.EcdsaP256Sha256
                bitLength <= 384 -> Algorithm.EcdsaP384Sha384
                else -> Algorithm.EcdsaP521Sha512
            }
        }
        // fallback: if we cannot inspect the curve, default to P-256
        return Algorithm.EcdsaP256Sha256
    }
}
