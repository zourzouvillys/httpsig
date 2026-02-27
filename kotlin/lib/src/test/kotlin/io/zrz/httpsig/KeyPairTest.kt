package io.zrz.httpsig

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class KeyPairTest {

    private val keysDir = Path.of("../../testdata/keys")

    // --- Auto-detection ---

    @Test
    fun `detects RSA-PSS from private key`() {
        val priv = loadPkcs8PrivateKey("rsa-pss.priv.pem", "RSA")
        val sk = Keys.signingKey("rsa-test", priv)
        assertEquals(Algorithm.RsaPssSha512, sk.algorithm)
        assertEquals("rsa-test", sk.keyId)
    }

    @Test
    fun `detects ECDSA P-256 from private key`() {
        val priv = loadEcPrivateKey("ecc-p256.priv.pem")
        val sk = Keys.signingKey("ec-test", priv)
        assertEquals(Algorithm.EcdsaP256Sha256, sk.algorithm)
    }

    @Test
    fun `detects Ed25519 from private key`() {
        val priv = loadPkcs8PrivateKey("ed25519.priv.pem", "Ed25519")
        val sk = Keys.signingKey("ed-test", priv)
        assertEquals(Algorithm.Ed25519, sk.algorithm)
    }

    @Test
    fun `detects RSA from public key`() {
        val pub = loadSpkiPublicKey("rsa-pss.pub.pem", "RSA")
        val vk = Keys.verifyingKey("rsa-test", pub)
        assertEquals(Algorithm.RsaPssSha512, vk.algorithm)
    }

    @Test
    fun `detects ECDSA from public key`() {
        val pub = loadSpkiPublicKey("ecc-p256.pub.pem", "EC")
        val vk = Keys.verifyingKey("ec-test", pub)
        assertEquals(Algorithm.EcdsaP256Sha256, vk.algorithm)
    }

    @Test
    fun `detects Ed25519 from public key`() {
        val pub = loadSpkiPublicKey("ed25519.pub.pem", "Ed25519")
        val vk = Keys.verifyingKey("ed-test", pub)
        assertEquals(Algorithm.Ed25519, vk.algorithm)
    }

    // --- KeyPair round-trips ---

    @Test
    fun `RSA key pair round-trip`() {
        val priv = loadPkcs8PrivateKey("rsa-pss.priv.pem", "RSA")
        val pub = loadSpkiPublicKey("rsa-pss.pub.pem", "RSA")
        val kp = Keys.keyPair("rsa-kp", priv, pub)

        assertEquals("rsa-kp", kp.keyId)
        assertEquals(Algorithm.RsaPssSha512, kp.algorithm)

        val data = "test data".toByteArray()
        val sig = kp.signingKey.sign(data)
        assertTrue(kp.verifyingKey.verify(data, sig))
    }

    @Test
    fun `ECDSA key pair round-trip`() {
        val priv = loadEcPrivateKey("ecc-p256.priv.pem")
        val pub = loadSpkiPublicKey("ecc-p256.pub.pem", "EC")
        val kp = Keys.keyPair("ec-kp", priv, pub)

        assertEquals(Algorithm.EcdsaP256Sha256, kp.algorithm)

        val data = "test data".toByteArray()
        val sig = kp.signingKey.sign(data)
        assertTrue(kp.verifyingKey.verify(data, sig))
    }

    @Test
    fun `Ed25519 key pair round-trip`() {
        val priv = loadPkcs8PrivateKey("ed25519.priv.pem", "Ed25519")
        val pub = loadSpkiPublicKey("ed25519.pub.pem", "Ed25519")
        val kp = Keys.keyPair("ed-kp", priv, pub)

        assertEquals(Algorithm.Ed25519, kp.algorithm)

        val data = "test data".toByteArray()
        val sig = kp.signingKey.sign(data)
        assertTrue(kp.verifyingKey.verify(data, sig))
    }

    @Test
    fun `HMAC key pair round-trip`() {
        val secret = "super-secret-key-at-least-32-bytes!!".toByteArray()
        val kp = Keys.hmacKeyPair("hmac-kp", secret)

        assertEquals(Algorithm.HmacSha256, kp.algorithm)
        assertEquals("hmac-kp", kp.keyId)

        val data = "test data".toByteArray()
        val sig = kp.signingKey.sign(data)
        assertTrue(kp.verifyingKey.verify(data, sig))
    }

    @Test
    fun `JCA key pair bridge`() {
        val keyGen = KeyPairGenerator.getInstance("Ed25519")
        val jcaKp = keyGen.generateKeyPair()
        val kp = Keys.keyPair("jca-ed", jcaKp)

        assertEquals(Algorithm.Ed25519, kp.algorithm)

        val data = "test data".toByteArray()
        val sig = kp.signingKey.sign(data)
        assertTrue(kp.verifyingKey.verify(data, sig))
    }

    // --- Validation ---

    @Test
    fun `rejects mismatched key IDs`() {
        val priv = loadPkcs8PrivateKey("ed25519.priv.pem", "Ed25519")
        val pub = loadSpkiPublicKey("ed25519.pub.pem", "Ed25519")
        val sk = Keys.ed25519SigningKey("a", priv)
        val vk = Keys.ed25519VerifyingKey("b", pub)
        assertThrows<IllegalArgumentException> { KeyPair(sk, vk) }
    }

    @Test
    fun `rejects mismatched algorithms`() {
        val rsaPriv = loadPkcs8PrivateKey("rsa-pss.priv.pem", "RSA")
        val edPub = loadSpkiPublicKey("ed25519.pub.pem", "Ed25519")
        val sk = Keys.rsaPSSSigningKey("x", rsaPriv)
        val vk = Keys.ed25519VerifyingKey("x", edPub)
        assertThrows<IllegalArgumentException> { KeyPair(sk, vk) }
    }

    // --- Key loading helpers (same approach as VectorTest) ---

    private fun loadPkcs8PrivateKey(filename: String, algorithm: String): PrivateKey {
        val der = decodePem(Files.readString(keysDir.resolve(filename)))
        val spec = PKCS8EncodedKeySpec(der)
        return try {
            KeyFactory.getInstance(algorithm).generatePrivate(spec)
        } catch (_: java.security.spec.InvalidKeySpecException) {
            if (algorithm == "RSA") {
                KeyFactory.getInstance("RSASSA-PSS").generatePrivate(spec)
            } else {
                throw IllegalStateException("cannot load private key: $filename as $algorithm")
            }
        }
    }

    private fun loadSpkiPublicKey(filename: String, algorithm: String): PublicKey {
        val der = decodePem(Files.readString(keysDir.resolve(filename)))
        val spec = X509EncodedKeySpec(der)
        return KeyFactory.getInstance(algorithm).generatePublic(spec)
    }

    private fun loadEcPrivateKey(filename: String): PrivateKey {
        val pem = Files.readString(keysDir.resolve(filename))
        if (pem.contains("BEGIN EC PRIVATE KEY")) {
            val sec1Der = decodePem(pem)
            val pkcs8Der = wrapEc256Sec1ToPkcs8(sec1Der)
            return KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8Der))
        }
        return loadPkcs8PrivateKey(filename, "EC")
    }

    /**
     * Wraps a SEC1 EC private key in a PKCS#8 envelope for P-256.
     * Exactly matches the approach in VectorTest.
     */
    private fun wrapEc256Sec1ToPkcs8(sec1Der: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()

        val version = byteArrayOf(0x02, 0x01, 0x00)

        val algId = byteArrayOf(
            0x30, 0x13,
            0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07,
        )

        val octetStringHeader = if (sec1Der.size < 128) {
            byteArrayOf(0x04, sec1Der.size.toByte())
        } else {
            byteArrayOf(0x04, 0x81.toByte(), sec1Der.size.toByte())
        }

        val totalSeqContent = version.size + algId.size + octetStringHeader.size + sec1Der.size

        if (totalSeqContent < 128) {
            out.write(byteArrayOf(0x30, totalSeqContent.toByte()))
        } else {
            out.write(byteArrayOf(0x30, 0x81.toByte(), totalSeqContent.toByte()))
        }

        out.write(version)
        out.write(algId)
        out.write(octetStringHeader)
        out.write(sec1Der)

        return out.toByteArray()
    }

    private fun decodePem(pem: String): ByteArray {
        val b64 = pem.replace(Regex("-----[A-Z ]+-----"), "")
            .replace(Regex("\\s+"), "")
        return Base64.getDecoder().decode(b64)
    }
}
