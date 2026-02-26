package com.zourzouvillys.httpsig

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

    private val PSS_PARAMS = PSSParameterSpec(
        "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1
    )

    fun rsaPssSign(key: PrivateKey, data: ByteArray): ByteArray = try {
        Signature.getInstance("RSASSA-PSS").apply {
            setParameter(PSS_PARAMS)
            initSign(key)
            update(data)
        }.sign()
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("RSA-PSS sign failed", e)
    }

    fun rsaPssVerify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean = try {
        Signature.getInstance("RSASSA-PSS").apply {
            setParameter(PSS_PARAMS)
            initVerify(key)
            update(data)
        }.verify(signature)
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("RSA-PSS verify failed", e)
    }

    // ---- ECDSA P-256 SHA-256 ----
    // RFC 9421 requires raw r||s (64 bytes). Java 15+ has SHA256withECDSAinP1363Format
    // which produces this format directly.

    private const val ECDSA_P1363 = "SHA256withECDSAinP1363Format"

    fun ecdsaSign(key: PrivateKey, data: ByteArray): ByteArray = try {
        Signature.getInstance(ECDSA_P1363).apply {
            initSign(key)
            update(data)
        }.sign()
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("ECDSA sign failed", e)
    }

    fun ecdsaVerify(key: PublicKey, data: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != 64) return false
        return try {
            Signature.getInstance(ECDSA_P1363).apply {
                initVerify(key)
                update(data)
            }.verify(signature)
        } catch (e: GeneralSecurityException) {
            throw HttpSigException("ECDSA verify failed", e)
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

    fun hmacSign(secret: ByteArray, data: ByteArray): ByteArray = try {
        Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(secret, "HmacSHA256"))
        }.doFinal(data)
    } catch (e: GeneralSecurityException) {
        throw HttpSigException("HMAC-SHA256 sign failed", e)
    }

    fun hmacVerify(secret: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        val expected = hmacSign(secret, data)
        return MessageDigest.isEqual(expected, signature)
    }
}
