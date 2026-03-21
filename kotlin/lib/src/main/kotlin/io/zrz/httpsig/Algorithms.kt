package io.zrz.httpsig

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Low-level crypto operations for each RFC 9421 algorithm.
 *
 * Not public API, just the plumbing that [Keys] delegates to.
 */
internal object Algorithms {

    // ---- RSA-PSS-SHA512 ----

    private val PSS_SHA512_PARAMS = PSSParameterSpec(
        "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1
    )

    fun rsaPssSha512Sign(key: PrivateKey, data: ByteArray): ByteArray =
        rsaPssSignWith(key, data, PSS_SHA512_PARAMS, "RSA-PSS-SHA512")

    fun rsaPssSha512Verify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean =
        rsaPssVerifyWith(key, data, signature, PSS_SHA512_PARAMS, "RSA-PSS-SHA512")

    // ---- RSA-PSS-SHA256 ----

    private val PSS_SHA256_PARAMS = PSSParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
    )

    fun rsaPssSha256Sign(key: PrivateKey, data: ByteArray): ByteArray =
        rsaPssSignWith(key, data, PSS_SHA256_PARAMS, "RSA-PSS-SHA256")

    fun rsaPssSha256Verify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean =
        rsaPssVerifyWith(key, data, signature, PSS_SHA256_PARAMS, "RSA-PSS-SHA256")

    // ---- RSA-PSS-SHA384 ----

    private val PSS_SHA384_PARAMS = PSSParameterSpec(
        "SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1
    )

    fun rsaPssSha384Sign(key: PrivateKey, data: ByteArray): ByteArray =
        rsaPssSignWith(key, data, PSS_SHA384_PARAMS, "RSA-PSS-SHA384")

    fun rsaPssSha384Verify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean =
        rsaPssVerifyWith(key, data, signature, PSS_SHA384_PARAMS, "RSA-PSS-SHA384")

    // ---- RSA-PSS helpers ----

    private fun rsaPssSignWith(
        key: PrivateKey,
        data: ByteArray,
        params: PSSParameterSpec,
        label: String,
    ): ByteArray = try {
        Signature.getInstance("RSASSA-PSS").apply {
            setParameter(params)
            initSign(key)
            update(data)
        }.sign()
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("$label sign failed", e)
    }

    private fun rsaPssVerifyWith(
        key: PublicKey,
        data: ByteArray,
        signature: ByteArray,
        params: PSSParameterSpec,
        label: String,
    ): Boolean = try {
        Signature.getInstance("RSASSA-PSS").apply {
            setParameter(params)
            initVerify(key)
            update(data)
        }.verify(signature)
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("$label verify failed", e)
    }

    // ---- RSA PKCS1v1.5 SHA-256 ----

    fun rsaV15Sha256Sign(key: PrivateKey, data: ByteArray): ByteArray = try {
        Signature.getInstance("SHA256withRSA").apply {
            initSign(key)
            update(data)
        }.sign()
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("RSA-v1_5-SHA256 sign failed", e)
    }

    fun rsaV15Sha256Verify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean = try {
        Signature.getInstance("SHA256withRSA").apply {
            initVerify(key)
            update(data)
        }.verify(signature)
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("RSA-v1_5-SHA256 verify failed", e)
    }

    // ---- ECDSA P-256 SHA-256 ----
    // RFC 9421 requires raw r||s (64 bytes). Java 15+ has SHA256withECDSAinP1363Format
    // which produces this format directly.

    private const val ECDSA_P256_P1363 = "SHA256withECDSAinP1363Format"

    fun ecdsaP256Sign(key: PrivateKey, data: ByteArray): ByteArray = try {
        Signature.getInstance(ECDSA_P256_P1363).apply {
            initSign(key)
            update(data)
        }.sign()
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("ECDSA-P256 sign failed", e)
    }

    fun ecdsaP256Verify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != 64) return false
        return try {
            Signature.getInstance(ECDSA_P256_P1363).apply {
                initVerify(key)
                update(data)
            }.verify(signature)
        } catch (e: GeneralSecurityException) {
            throw HttpSigException("ECDSA-P256 verify failed", e)
        }
    }

    // ---- ECDSA P-384 SHA-384 ----
    // Raw r||s = 48+48 = 96 bytes

    private const val ECDSA_P384_P1363 = "SHA384withECDSAinP1363Format"

    fun ecdsaP384Sign(key: PrivateKey, data: ByteArray): ByteArray = try {
        Signature.getInstance(ECDSA_P384_P1363).apply {
            initSign(key)
            update(data)
        }.sign()
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("ECDSA-P384 sign failed", e)
    }

    fun ecdsaP384Verify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != 96) return false
        return try {
            Signature.getInstance(ECDSA_P384_P1363).apply {
                initVerify(key)
                update(data)
            }.verify(signature)
        } catch (e: GeneralSecurityException) {
            throw HttpSigException("ECDSA-P384 verify failed", e)
        }
    }

    // ---- ECDSA P-521 SHA-512 ----
    // Raw r||s = 66+66 = 132 bytes

    private const val ECDSA_P521_P1363 = "SHA512withECDSAinP1363Format"

    fun ecdsaP521Sign(key: PrivateKey, data: ByteArray): ByteArray = try {
        Signature.getInstance(ECDSA_P521_P1363).apply {
            initSign(key)
            update(data)
        }.sign()
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("ECDSA-P521 sign failed", e)
    }

    fun ecdsaP521Verify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != 132) return false
        return try {
            Signature.getInstance(ECDSA_P521_P1363).apply {
                initVerify(key)
                update(data)
            }.verify(signature)
        } catch (e: GeneralSecurityException) {
            throw HttpSigException("ECDSA-P521 verify failed", e)
        }
    }

    // ---- Ed25519 ----

    fun ed25519Sign(key: PrivateKey, data: ByteArray): ByteArray = try {
        Signature.getInstance("Ed25519").apply {
            initSign(key)
            update(data)
        }.sign()
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("Ed25519 sign failed", e)
    }

    fun ed25519Verify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean = try {
        Signature.getInstance("Ed25519").apply {
            initVerify(key)
            update(data)
        }.verify(signature)
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("Ed25519 verify failed", e)
    }

    // ---- HMAC-SHA256 ----

    fun hmacSha256Sign(secret: ByteArray, data: ByteArray): ByteArray =
        hmacSignWith(secret, data, "HmacSHA256")

    fun hmacSha256Verify(secret: ByteArray, data: ByteArray, signature: ByteArray): Boolean =
        hmacVerifyWith(secret, data, signature, "HmacSHA256")

    // ---- HMAC-SHA384 ----

    fun hmacSha384Sign(secret: ByteArray, data: ByteArray): ByteArray =
        hmacSignWith(secret, data, "HmacSHA384")

    fun hmacSha384Verify(secret: ByteArray, data: ByteArray, signature: ByteArray): Boolean =
        hmacVerifyWith(secret, data, signature, "HmacSHA384")

    // ---- HMAC-SHA512 ----

    fun hmacSha512Sign(secret: ByteArray, data: ByteArray): ByteArray =
        hmacSignWith(secret, data, "HmacSHA512")

    fun hmacSha512Verify(secret: ByteArray, data: ByteArray, signature: ByteArray): Boolean =
        hmacVerifyWith(secret, data, signature, "HmacSHA512")

    // ---- HMAC helpers ----

    private fun hmacSignWith(secret: ByteArray, data: ByteArray, jcaAlgorithm: String): ByteArray = try {
        Mac.getInstance(jcaAlgorithm).apply {
            init(SecretKeySpec(secret, jcaAlgorithm))
        }.doFinal(data)
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("$jcaAlgorithm sign failed", e)
    }

    private fun hmacVerifyWith(
        secret: ByteArray,
        data: ByteArray,
        signature: ByteArray,
        jcaAlgorithm: String,
    ): Boolean {
        val expected = hmacSignWith(secret, data, jcaAlgorithm)
        return MessageDigest.isEqual(expected, signature)
    }
}
