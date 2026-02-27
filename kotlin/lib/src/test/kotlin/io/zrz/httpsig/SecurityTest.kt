package io.zrz.httpsig

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.URI
import java.time.Duration
import java.time.Instant
import java.util.function.Supplier

/**
 * Security regression tests: clock skew enforcement, algorithm mismatch
 * rejection, and VerifyResult field correctness.
 */
class SecurityTest {

    companion object {
        private val SECRET = "hmac-secret-key-that-is-at-least-256-bits-long!!".toByteArray()
        private const val KEY_ID = "sec-test-key"

        private fun hmacKey(): Keys.HmacKey = Keys.hmacSHA256Key(KEY_ID, SECRET)

        private fun simpleMessage(): RawMessage.Request = RawMessage.request(
            "POST",
            URI.create("https://example.com/resource"),
            mapOf("content-type" to listOf("application/json")),
        )

        /**
         * Sign the simple message, returning a signed [RawMessage] ready for verification.
         * The [created] epoch is baked into the Signature-Input.
         */
        private fun signMessage(
            createdEpoch: Long,
            includeAlgorithm: Boolean = false,
        ): RawMessage.Request {
            val key = hmacKey()
            val builder = SignatureParameters.builder()
                .component("@method")
                .component("content-type")
                .keyId(KEY_ID)
                .createdEpoch(createdEpoch)
            if (includeAlgorithm) {
                builder.algorithm(Algorithm.HmacSha256)
            }
            val params = builder.build()
            val result = Signer.sign(simpleMessage(), "sig1", params, key)
            return RawMessage.request(
                "POST",
                URI.create("https://example.com/resource"),
                mapOf(
                    "content-type" to listOf("application/json"),
                    "signature-input" to listOf(Signer.signatureInputHeader(result)),
                    "signature" to listOf(Signer.signatureHeader(result)),
                ),
            )
        }
    }

    // ----------------------------------------------------------------
    // 1. Future-dated signature rejection
    // ----------------------------------------------------------------

    @Test
    fun `future-dated signature rejected with tight clock skew`() {
        val now = Instant.ofEpochSecond(1_700_000_000)
        val oneHourAhead = now.plusSeconds(3600).epochSecond

        val signed = signMessage(oneHourAhead)

        val ex = assertThrows<HttpSigException> {
            Verifier.verify(
                signed,
                { _, _ -> hmacKey() },
                Verifier.VerifyOptions(
                    maxClockSkew = Duration.ofSeconds(30),
                    now = Supplier { now },
                ),
            )
        }
        assertNotNull(ex.message)
    }

    @Test
    fun `future-dated signature accepted with generous clock skew`() {
        val now = Instant.ofEpochSecond(1_700_000_000)
        val oneHourAhead = now.plusSeconds(3600).epochSecond

        val signed = signMessage(oneHourAhead)

        val result = Verifier.verify(
            signed,
            { _, _ -> hmacKey() },
            Verifier.VerifyOptions(
                maxClockSkew = Duration.ofHours(2),
                now = Supplier { now },
            ),
        )
        assertEquals("sig1", result.label)
        assertEquals(KEY_ID, result.keyId)
    }

    @Test
    fun `future-dated signature accepted with no clock skew check`() {
        val now = Instant.ofEpochSecond(1_700_000_000)
        val oneHourAhead = now.plusSeconds(3600).epochSecond

        val signed = signMessage(oneHourAhead)

        // null maxClockSkew (the default) means no future-date checking
        val result = Verifier.verify(
            signed,
            { _, _ -> hmacKey() },
            Verifier.VerifyOptions(
                maxClockSkew = null,
                now = Supplier { now },
            ),
        )
        assertEquals("sig1", result.label)
    }

    @Test
    fun `expired signature rejected by default`() {
        val now = Instant.ofEpochSecond(1_700_000_000)
        val expired = now.minusSeconds(60).epochSecond

        val key = hmacKey()
        val params = SignatureParameters.builder()
            .component("@method")
            .keyId(KEY_ID)
            .algorithm(Algorithm.HmacSha256)
            .createdEpoch(now.minusSeconds(120).epochSecond)
            .expiresEpoch(expired)
            .build()
        val result = Signer.sign(simpleMessage(), "sig1", params, key)
        val signed = RawMessage.request(
            "POST",
            URI.create("https://example.com/resource"),
            mapOf(
                "content-type" to listOf("application/json"),
                "signature-input" to listOf(Signer.signatureInputHeader(result)),
                "signature" to listOf(Signer.signatureHeader(result)),
            ),
        )

        assertThrows<HttpSigException> {
            Verifier.verify(
                signed,
                { _, _ -> hmacKey() },
                Verifier.VerifyOptions(now = Supplier { now }),
            )
        }
    }

    @Test
    fun `expired signature accepted when rejectExpired is false`() {
        val now = Instant.ofEpochSecond(1_700_000_000)
        val expired = now.minusSeconds(60).epochSecond

        val key = hmacKey()
        val params = SignatureParameters.builder()
            .component("@method")
            .keyId(KEY_ID)
            .algorithm(Algorithm.HmacSha256)
            .createdEpoch(now.minusSeconds(120).epochSecond)
            .expiresEpoch(expired)
            .build()
        val result = Signer.sign(simpleMessage(), "sig1", params, key)
        val signed = RawMessage.request(
            "POST",
            URI.create("https://example.com/resource"),
            mapOf(
                "content-type" to listOf("application/json"),
                "signature-input" to listOf(Signer.signatureInputHeader(result)),
                "signature" to listOf(Signer.signatureHeader(result)),
            ),
        )

        val verifyResult = Verifier.verify(
            signed,
            { _, _ -> hmacKey() },
            Verifier.VerifyOptions(
                rejectExpired = false,
                now = Supplier { now },
            ),
        )
        assertEquals("sig1", verifyResult.label)
    }

    // ----------------------------------------------------------------
    // 2. Algorithm mismatch rejection
    // ----------------------------------------------------------------

    @Test
    fun `algorithm mismatch between signature-input and key is rejected`() {
        // Sign with HMAC key, including alg="hmac-sha256" in signature params
        val signed = signMessage(1_700_000_000, includeAlgorithm = true)

        // Tamper: rewrite Signature-Input to claim alg="ed25519"
        val origSigInput = signed.headerValues("signature-input").single()
        val tamperedSigInput = origSigInput.replace("alg=\"hmac-sha256\"", "alg=\"ed25519\"")
        // Sanity: make sure the replacement actually changed something
        assert(tamperedSigInput != origSigInput) { "tamper did not modify Signature-Input" }

        val tamperedMsg = RawMessage.request(
            "POST",
            URI.create("https://example.com/resource"),
            mapOf(
                "content-type" to listOf("application/json"),
                "signature-input" to listOf(tamperedSigInput),
                "signature" to signed.headerValues("signature"),
            ),
        )

        // KeyProvider returns the real HMAC key (algorithm = HmacSha256),
        // but the input now claims ed25519, so verification must fail.
        val ex = assertThrows<HttpSigException> {
            Verifier.verify(tamperedMsg, { _, _ -> hmacKey() })
        }
        assertNotNull(ex.message)
    }

    // ----------------------------------------------------------------
    // 3. VerifyResult returns the key's algorithm
    // ----------------------------------------------------------------

    @Test
    fun `verify result contains key algorithm`() {
        val signed = signMessage(1_700_000_000)

        val result = Verifier.verify(signed, { _, _ -> hmacKey() })

        assertEquals(Algorithm.HmacSha256, result.algorithm)
    }
}
