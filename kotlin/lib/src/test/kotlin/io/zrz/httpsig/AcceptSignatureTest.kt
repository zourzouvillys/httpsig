package io.zrz.httpsig

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.URI

/**
 * Tests for Accept-Signature header building, parsing, and integration
 * with the verifier via SignatureRequirements.
 */
class AcceptSignatureTest {

    @Test
    fun `round-trip build and parse`() {
        val req = SignatureRequirements(
            components = listOf(
                ComponentIdentifier.of("@method"),
                ComponentIdentifier.of("@authority"),
                ComponentIdentifier.of("content-digest"),
            ),
            keyId = "server-key-1",
            algorithm = Algorithm.EcdsaP256Sha256,
            tag = "myapp",
            requireCreated = true,
            requireExpires = true,
        )

        val entries = linkedMapOf("sig1" to req)
        val headerValue = AcceptSignature.build(entries)
        assertNotNull(headerValue)
        assertTrue(headerValue.isNotEmpty())

        val parsed = AcceptSignature.parse(headerValue)
        assertEquals(1, parsed.size)
        assertTrue(parsed.containsKey("sig1"))

        val parsedReq = parsed["sig1"]!!
        assertEquals(3, parsedReq.components.size)
        assertEquals("@method", parsedReq.components[0].name)
        assertEquals("@authority", parsedReq.components[1].name)
        assertEquals("content-digest", parsedReq.components[2].name)
        assertEquals("server-key-1", parsedReq.keyId)
        assertEquals(Algorithm.EcdsaP256Sha256, parsedReq.algorithm)
        assertEquals("myapp", parsedReq.tag)
        assertTrue(parsedReq.requireCreated)
        assertTrue(parsedReq.requireExpires)
    }

    @Test
    fun `parse RFC-style example`() {
        val header =
            """sig1=("@method" "@authority" "content-digest");keyid="server-key-1";alg="ecdsa-p256-sha256";created;expires;tag="myapp""""
        val parsed = AcceptSignature.parse(header)
        assertEquals(1, parsed.size)

        val req = parsed["sig1"]!!
        assertEquals(3, req.components.size)
        assertEquals("@method", req.components[0].name)
        assertEquals("@authority", req.components[1].name)
        assertEquals("content-digest", req.components[2].name)
        assertEquals("server-key-1", req.keyId)
        assertEquals(Algorithm.EcdsaP256Sha256, req.algorithm)
        assertEquals("myapp", req.tag)
        assertTrue(req.requireCreated)
        assertTrue(req.requireExpires)
    }

    @Test
    fun `multiple entries`() {
        val req1 = SignatureRequirements(
            components = listOf(ComponentIdentifier.of("@method")),
            keyId = "key-1",
            algorithm = Algorithm.HmacSha256,
        )

        val req2 = SignatureRequirements(
            components = listOf(
                ComponentIdentifier.of("@method"),
                ComponentIdentifier.of("@path"),
            ),
            keyId = "key-2",
            algorithm = Algorithm.Ed25519,
            tag = "proxy",
        )

        val entries = linkedMapOf("sig1" to req1, "sig2" to req2)
        val headerValue = AcceptSignature.build(entries)
        val parsed = AcceptSignature.parse(headerValue)

        assertEquals(2, parsed.size)

        val p1 = parsed["sig1"]!!
        assertEquals(1, p1.components.size)
        assertEquals("key-1", p1.keyId)
        assertEquals(Algorithm.HmacSha256, p1.algorithm)

        val p2 = parsed["sig2"]!!
        assertEquals(2, p2.components.size)
        assertEquals("key-2", p2.keyId)
        assertEquals(Algorithm.Ed25519, p2.algorithm)
        assertEquals("proxy", p2.tag)
    }

    @Test
    fun `component with params`() {
        val req = SignatureRequirements(
            components = listOf(ComponentIdentifier.queryParam("foo")),
        )

        val entries = linkedMapOf("sig1" to req)
        val headerValue = AcceptSignature.build(entries)
        assertTrue(headerValue.contains("\"@query-param\";name=\"foo\""))

        val parsed = AcceptSignature.parse(headerValue)
        val parsedReq = parsed["sig1"]!!
        assertEquals(1, parsedReq.components.size)
        assertEquals("@query-param", parsedReq.components[0].name)
        assertEquals("foo", parsedReq.components[0].paramString("name"))
    }

    @Test
    fun `empty components`() {
        val req = SignatureRequirements(keyId = "k1")

        val entries = linkedMapOf("sig1" to req)
        val headerValue = AcceptSignature.build(entries)
        assertTrue(headerValue.contains("()"))

        val parsed = AcceptSignature.parse(headerValue)
        val parsedReq = parsed["sig1"]!!
        assertEquals(0, parsedReq.components.size)
        assertEquals("k1", parsedReq.keyId)
    }

    @Test
    fun `toSignatureParameters with all fields`() {
        val req = SignatureRequirements(
            components = listOf(
                ComponentIdentifier.of("@method"),
                ComponentIdentifier.of("@authority"),
            ),
            keyId = "test-key",
            algorithm = Algorithm.HmacSha256,
            tag = "myapp",
        )

        val params = req.toSignatureParameters(1618884473L, 1618884573L, "abc123")
        assertEquals(2, params.components.size)
        assertEquals("@method", params.components[0].name)
        assertEquals("@authority", params.components[1].name)
        assertEquals("test-key", params.keyId)
        assertEquals(Algorithm.HmacSha256, params.algorithm)
        assertEquals("myapp", params.tag)
        assertEquals(1618884473L, params.created)
        assertEquals(1618884573L, params.expires)
        assertEquals("abc123", params.nonce)
    }

    @Test
    fun `toSignatureParameters with null optionals`() {
        val req = SignatureRequirements(
            components = listOf(ComponentIdentifier.of("@method")),
        )

        val params = req.toSignatureParameters()
        assertEquals(1, params.components.size)
        assertNull(params.keyId)
        assertNull(params.algorithm)
        assertNull(params.tag)
        assertNull(params.created)
        assertNull(params.expires)
        assertNull(params.nonce)
    }

    @Test
    fun `verifier with matching requirements`() {
        val secret = "accept-sig-test-secret-long-enough!!".toByteArray()
        val signingKey = Keys.hmacSHA256Key("test-key", secret)
        val verifyingKey = Keys.hmacSHA256Key("test-key", secret)

        val request = RawMessage.request(
            "POST",
            URI.create("https://example.com/api"),
            mapOf("content-type" to listOf("application/json")),
        )

        val params = SignatureParameters.builder()
            .component("@method")
            .component("@authority")
            .keyId("test-key")
            .algorithm(Algorithm.HmacSha256)
            .tag("myapp")
            .createdEpoch(1618884473L)
            .build()

        val result = Signer.sign(request, "sig1", params, signingKey)
        val signedRequest = RawMessage.request(
            "POST",
            URI.create("https://example.com/api"),
            mapOf(
                "content-type" to listOf("application/json"),
                "signature-input" to listOf(Signer.signatureInputHeader(result)),
                "signature" to listOf(Signer.signatureHeader(result)),
            ),
        )

        // matching requirements should verify
        val requirements = SignatureRequirements(
            components = listOf(ComponentIdentifier.of("@method")),
            keyId = "test-key",
            algorithm = Algorithm.HmacSha256,
            tag = "myapp",
        )

        val options = Verifier.VerifyOptions(
            requirements = requirements,
            rejectExpired = false,
        )

        val verifyResult = Verifier.verify(signedRequest, { _, _ -> verifyingKey }, options)
        assertEquals("sig1", verifyResult.label)
        assertEquals("test-key", verifyResult.keyId)
    }

    @Test
    fun `verifier rejects keyId mismatch`() {
        val secret = "keyid-mismatch-test-secret-long!!!".toByteArray()
        val signingKey = Keys.hmacSHA256Key("actual-key", secret)
        val verifyingKey = Keys.hmacSHA256Key("actual-key", secret)

        val request = RawMessage.request("GET", URI.create("https://example.com/"), mapOf())

        val params = SignatureParameters.builder()
            .component("@method")
            .keyId("actual-key")
            .algorithm(Algorithm.HmacSha256)
            .createdEpoch(1618884473L)
            .build()

        val result = Signer.sign(request, "sig1", params, signingKey)
        val signedRequest = RawMessage.request(
            "GET",
            URI.create("https://example.com/"),
            mapOf(
                "signature-input" to listOf(Signer.signatureInputHeader(result)),
                "signature" to listOf(Signer.signatureHeader(result)),
            ),
        )

        val requirements = SignatureRequirements(
            components = listOf(ComponentIdentifier.of("@method")),
            keyId = "expected-key",
        )

        val options = Verifier.VerifyOptions(
            requirements = requirements,
            rejectExpired = false,
        )

        assertThrows(HttpSigException::class.java) {
            Verifier.verify(signedRequest, { _, _ -> verifyingKey }, options)
        }
    }

    @Test
    fun `verifier rejects tag mismatch`() {
        val secret = "tag-mismatch-test-secret-long!!!!".toByteArray()
        val signingKey = Keys.hmacSHA256Key("k", secret)
        val verifyingKey = Keys.hmacSHA256Key("k", secret)

        val request = RawMessage.request("GET", URI.create("https://example.com/"), mapOf())

        val params = SignatureParameters.builder()
            .component("@method")
            .keyId("k")
            .algorithm(Algorithm.HmacSha256)
            .tag("wrong-tag")
            .createdEpoch(1618884473L)
            .build()

        val result = Signer.sign(request, "sig1", params, signingKey)
        val signedRequest = RawMessage.request(
            "GET",
            URI.create("https://example.com/"),
            mapOf(
                "signature-input" to listOf(Signer.signatureInputHeader(result)),
                "signature" to listOf(Signer.signatureHeader(result)),
            ),
        )

        val requirements = SignatureRequirements(
            components = listOf(ComponentIdentifier.of("@method")),
            tag = "expected-tag",
        )

        val options = Verifier.VerifyOptions(
            requirements = requirements,
            rejectExpired = false,
        )

        assertThrows(HttpSigException::class.java) {
            Verifier.verify(signedRequest, { _, _ -> verifyingKey }, options)
        }
    }

    @Test
    fun `verifier rejects algorithm mismatch`() {
        val secret = "alg-mismatch-test-secret-long!!!!".toByteArray()
        val signingKey = Keys.hmacSHA256Key("k", secret)
        val verifyingKey = Keys.hmacSHA256Key("k", secret)

        val request = RawMessage.request("GET", URI.create("https://example.com/"), mapOf())

        val params = SignatureParameters.builder()
            .component("@method")
            .keyId("k")
            .algorithm(Algorithm.HmacSha256)
            .createdEpoch(1618884473L)
            .build()

        val result = Signer.sign(request, "sig1", params, signingKey)
        val signedRequest = RawMessage.request(
            "GET",
            URI.create("https://example.com/"),
            mapOf(
                "signature-input" to listOf(Signer.signatureInputHeader(result)),
                "signature" to listOf(Signer.signatureHeader(result)),
            ),
        )

        val requirements = SignatureRequirements(
            components = listOf(ComponentIdentifier.of("@method")),
            algorithm = Algorithm.Ed25519,
        )

        val options = Verifier.VerifyOptions(
            requirements = requirements,
            rejectExpired = false,
        )

        assertThrows(HttpSigException::class.java) {
            Verifier.verify(signedRequest, { _, _ -> verifyingKey }, options)
        }
    }

    @Test
    fun `backward-compat requiredComponents still works`() {
        val secret = "backward-compat-test-secret-long!".toByteArray()
        val signingKey = Keys.hmacSHA256Key("k", secret)
        val verifyingKey = Keys.hmacSHA256Key("k", secret)

        val request = RawMessage.request("GET", URI.create("https://example.com/"), mapOf())

        val params = SignatureParameters.builder()
            .component("@method")
            .keyId("k")
            .algorithm(Algorithm.HmacSha256)
            .createdEpoch(1618884473L)
            .build()

        val result = Signer.sign(request, "sig1", params, signingKey)
        val signedRequest = RawMessage.request(
            "GET",
            URI.create("https://example.com/"),
            mapOf(
                "signature-input" to listOf(Signer.signatureInputHeader(result)),
                "signature" to listOf(Signer.signatureHeader(result)),
            ),
        )

        // old-style requiredComponents still works
        val options = Verifier.VerifyOptions(
            requiredComponents = listOf(ComponentIdentifier.of("@method")),
            rejectExpired = false,
        )

        val verifyResult = Verifier.verify(signedRequest, { _, _ -> verifyingKey }, options)
        assertEquals("sig1", verifyResult.label)
    }
}
