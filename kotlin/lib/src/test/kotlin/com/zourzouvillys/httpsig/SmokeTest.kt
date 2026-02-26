package com.zourzouvillys.httpsig

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import java.net.URI

/**
 * Basic smoke tests to verify the library wires together correctly.
 */
class SmokeTest {

    @Test
    fun `algorithm round-trips from value`() {
        for (alg in listOf(
            Algorithm.RsaPssSha512,
            Algorithm.EcdsaP256Sha256,
            Algorithm.Ed25519,
            Algorithm.HmacSha256,
        )) {
            assertEquals(alg, Algorithm.fromValue(alg.value))
        }
    }

    @Test
    fun `component identifier serialization`() {
        val cid = ComponentIdentifier.of("@method")
        assertEquals("\"@method\"", SFV.serializeComponentId(cid))

        val qp = ComponentIdentifier.queryParam("Pet")
        assertEquals("\"@query-param\";name=\"Pet\"", SFV.serializeComponentId(qp))
    }

    @Test
    fun `raw message request`() {
        val msg = RawMessage.request(
            "GET",
            URI.create("https://example.com/path"),
            mapOf("Content-Type" to listOf("application/json")),
        )
        assertEquals(true, msg.isRequest)
        assertEquals("GET", msg.method)
        assertEquals(listOf("application/json"), msg.headerValues("content-type"))
        assertEquals(emptyList<String>(), msg.headerValues("x-missing"))
    }

    @Test
    fun `hmac sign and verify round trip`() {
        val secret = "super-secret-key-that-is-at-least-256-bits-long!!".toByteArray()
        val key = Keys.hmacSHA256Key("test-key", secret)

        val msg = RawMessage.request(
            "POST",
            URI.create("https://example.com/test"),
            mapOf("content-type" to listOf("application/json")),
        )

        val params = SignatureParameters.builder()
            .component("@method")
            .component("@authority")
            .component("content-type")
            .keyId("test-key")
            .createdEpoch(1618884473)
            .build()

        val result = Signer.sign(msg, "sig1", params, key)
        assertNotNull(result.signature)

        // build signed message for verification
        val signedMsg = RawMessage.request(
            "POST",
            URI.create("https://example.com/test"),
            mapOf(
                "content-type" to listOf("application/json"),
                "signature-input" to listOf(Signer.signatureInputHeader(result)),
                "signature" to listOf(Signer.signatureHeader(result)),
            ),
        )

        val verifyResult = Verifier.verify(signedMsg, { _, _ -> key })
        assertEquals("sig1", verifyResult.label)
        assertEquals("test-key", verifyResult.keyId)
    }
}
