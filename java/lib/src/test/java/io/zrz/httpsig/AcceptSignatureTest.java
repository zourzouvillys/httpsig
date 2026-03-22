package io.zrz.httpsig;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Tests for Accept-Signature header building, parsing, and integration
 * with the verifier via SignatureRequirements.
 */
class AcceptSignatureTest {

    @Test
    void roundTrip() throws Exception {
        var req = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .component("@authority")
            .component("content-digest")
            .keyId("server-key-1")
            .algorithm(Algorithm.ECDSA_P256_SHA256)
            .tag("myapp")
            .requireCreated(true)
            .requireExpires(true)
            .build();

        var entries = new LinkedHashMap<String, AcceptSignature.SignatureRequirements>();
        entries.put("sig1", req);

        String headerValue = AcceptSignature.build(entries);
        assertNotNull(headerValue);
        assertFalse(headerValue.isEmpty());

        var parsed = AcceptSignature.parse(headerValue);
        assertEquals(1, parsed.size());
        assertTrue(parsed.containsKey("sig1"));

        var parsedReq = parsed.get("sig1");
        assertEquals(3, parsedReq.components().size());
        assertEquals("@method", parsedReq.components().get(0).name());
        assertEquals("@authority", parsedReq.components().get(1).name());
        assertEquals("content-digest", parsedReq.components().get(2).name());
        assertEquals("server-key-1", parsedReq.keyId());
        assertEquals(Algorithm.ECDSA_P256_SHA256, parsedReq.algorithm());
        assertEquals("myapp", parsedReq.tag());
        assertTrue(parsedReq.requireCreated());
        assertTrue(parsedReq.requireExpires());
    }

    @Test
    void parseRfcStyleExample() throws Exception {
        String header = "sig1=(\"@method\" \"@authority\" \"content-digest\");keyid=\"server-key-1\";alg=\"ecdsa-p256-sha256\";created;expires;tag=\"myapp\"";
        var parsed = AcceptSignature.parse(header);
        assertEquals(1, parsed.size());

        var req = parsed.get("sig1");
        assertNotNull(req);
        assertEquals(3, req.components().size());
        assertEquals("@method", req.components().get(0).name());
        assertEquals("@authority", req.components().get(1).name());
        assertEquals("content-digest", req.components().get(2).name());
        assertEquals("server-key-1", req.keyId());
        assertEquals(Algorithm.ECDSA_P256_SHA256, req.algorithm());
        assertEquals("myapp", req.tag());
        assertTrue(req.requireCreated());
        assertTrue(req.requireExpires());
    }

    @Test
    void multipleEntries() throws Exception {
        var req1 = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .keyId("key-1")
            .algorithm(Algorithm.HMAC_SHA256)
            .build();

        var req2 = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .component("@path")
            .keyId("key-2")
            .algorithm(Algorithm.ED25519)
            .tag("proxy")
            .build();

        var entries = new LinkedHashMap<String, AcceptSignature.SignatureRequirements>();
        entries.put("sig1", req1);
        entries.put("sig2", req2);

        String headerValue = AcceptSignature.build(entries);
        var parsed = AcceptSignature.parse(headerValue);

        assertEquals(2, parsed.size());

        var p1 = parsed.get("sig1");
        assertEquals(1, p1.components().size());
        assertEquals("key-1", p1.keyId());
        assertEquals(Algorithm.HMAC_SHA256, p1.algorithm());

        var p2 = parsed.get("sig2");
        assertEquals(2, p2.components().size());
        assertEquals("key-2", p2.keyId());
        assertEquals(Algorithm.ED25519, p2.algorithm());
        assertEquals("proxy", p2.tag());
    }

    @Test
    void componentWithParams() throws Exception {
        var req = AcceptSignature.SignatureRequirements.builder()
            .component(ComponentIdentifier.queryParam("foo"))
            .build();

        var entries = new LinkedHashMap<String, AcceptSignature.SignatureRequirements>();
        entries.put("sig1", req);

        String headerValue = AcceptSignature.build(entries);
        assertTrue(headerValue.contains("\"@query-param\";name=\"foo\""));

        var parsed = AcceptSignature.parse(headerValue);
        var parsedReq = parsed.get("sig1");
        assertEquals(1, parsedReq.components().size());
        assertEquals("@query-param", parsedReq.components().get(0).name());
        assertEquals("foo", parsedReq.components().get(0).paramString("name"));
    }

    @Test
    void emptyComponents() throws Exception {
        var req = AcceptSignature.SignatureRequirements.builder()
            .keyId("k1")
            .build();

        var entries = new LinkedHashMap<String, AcceptSignature.SignatureRequirements>();
        entries.put("sig1", req);

        String headerValue = AcceptSignature.build(entries);
        assertTrue(headerValue.contains("()"));

        var parsed = AcceptSignature.parse(headerValue);
        var parsedReq = parsed.get("sig1");
        assertEquals(0, parsedReq.components().size());
        assertEquals("k1", parsedReq.keyId());
    }

    @Test
    void toSignatureParameters() {
        var req = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .component("@authority")
            .keyId("test-key")
            .algorithm(Algorithm.HMAC_SHA256)
            .tag("myapp")
            .build();

        var params = req.toSignatureParameters(1618884473L, 1618884573L, "abc123");
        assertEquals(2, params.components().size());
        assertEquals("@method", params.components().get(0).name());
        assertEquals("@authority", params.components().get(1).name());
        assertEquals("test-key", params.keyId());
        assertEquals(Algorithm.HMAC_SHA256, params.algorithm());
        assertEquals("myapp", params.tag());
        assertEquals(1618884473L, params.created());
        assertEquals(1618884573L, params.expires());
        assertEquals("abc123", params.nonce());
    }

    @Test
    void toSignatureParametersNullOptionals() {
        var req = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .build();

        var params = req.toSignatureParameters(null, null, null);
        assertEquals(1, params.components().size());
        assertNull(params.keyId());
        assertNull(params.algorithm());
        assertNull(params.tag());
        assertNull(params.created());
        assertNull(params.expires());
        assertNull(params.nonce());
    }

    @Test
    void verifierWithRequirements() throws Exception {
        byte[] secret = "accept-sig-test-secret-long-enough!!".getBytes();
        var signingKey = Keys.hmacSHA256Key("test-key", secret);
        var verifyingKey = Keys.hmacSHA256Key("test-key", secret);

        var request = RawMessage.request("POST", URI.create("https://example.com/api"),
            Map.of("content-type", List.of("application/json")));

        var params = SignatureParameters.builder()
            .component("@method")
            .component("@authority")
            .keyId("test-key")
            .algorithm(Algorithm.HMAC_SHA256)
            .tag("myapp")
            .createdEpoch(1618884473L)
            .build();

        var result = Signer.sign(request, "sig1", params, signingKey, null);
        var signedRequest = RawMessage.request("POST", URI.create("https://example.com/api"),
            Map.of(
                "content-type", List.of("application/json"),
                "signature-input", List.of(Signer.signatureInputHeader(result)),
                "signature", List.of(Signer.signatureHeader(result))
            ));

        // matching requirements should verify
        var requirements = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .keyId("test-key")
            .algorithm(Algorithm.HMAC_SHA256)
            .tag("myapp")
            .build();

        var options = Verifier.VerifyOptions.builder()
            .requirements(requirements)
            .rejectExpired(false)
            .build();

        var verifyResult = Verifier.verify(signedRequest, (keyId, alg) -> verifyingKey, options, null);
        assertEquals("sig1", verifyResult.label());
        assertEquals("test-key", verifyResult.keyId());
    }

    @Test
    void verifierRejectsKeyIdMismatch() throws Exception {
        byte[] secret = "keyid-mismatch-test-secret-long!!!".getBytes();
        var signingKey = Keys.hmacSHA256Key("actual-key", secret);
        var verifyingKey = Keys.hmacSHA256Key("actual-key", secret);

        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());

        var params = SignatureParameters.builder()
            .component("@method")
            .keyId("actual-key")
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1618884473L)
            .build();

        var result = Signer.sign(request, "sig1", params, signingKey, null);
        var signedRequest = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of(
                "signature-input", List.of(Signer.signatureInputHeader(result)),
                "signature", List.of(Signer.signatureHeader(result))
            ));

        var requirements = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .keyId("expected-key")
            .build();

        var options = Verifier.VerifyOptions.builder()
            .requirements(requirements)
            .rejectExpired(false)
            .build();

        assertThrows(HttpSigException.class,
            () -> Verifier.verify(signedRequest, (keyId, alg) -> verifyingKey, options, null));
    }

    @Test
    void verifierRejectsTagMismatch() throws Exception {
        byte[] secret = "tag-mismatch-test-secret-long!!!!".getBytes();
        var signingKey = Keys.hmacSHA256Key("k", secret);
        var verifyingKey = Keys.hmacSHA256Key("k", secret);

        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());

        var params = SignatureParameters.builder()
            .component("@method")
            .keyId("k")
            .algorithm(Algorithm.HMAC_SHA256)
            .tag("wrong-tag")
            .createdEpoch(1618884473L)
            .build();

        var result = Signer.sign(request, "sig1", params, signingKey, null);
        var signedRequest = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of(
                "signature-input", List.of(Signer.signatureInputHeader(result)),
                "signature", List.of(Signer.signatureHeader(result))
            ));

        var requirements = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .tag("expected-tag")
            .build();

        var options = Verifier.VerifyOptions.builder()
            .requirements(requirements)
            .rejectExpired(false)
            .build();

        assertThrows(HttpSigException.class,
            () -> Verifier.verify(signedRequest, (keyId, alg) -> verifyingKey, options, null));
    }

    @Test
    void verifierRejectsAlgorithmMismatch() throws Exception {
        byte[] secret = "alg-mismatch-test-secret-long!!!!".getBytes();
        var signingKey = Keys.hmacSHA256Key("k", secret);
        var verifyingKey = Keys.hmacSHA256Key("k", secret);

        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());

        var params = SignatureParameters.builder()
            .component("@method")
            .keyId("k")
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1618884473L)
            .build();

        var result = Signer.sign(request, "sig1", params, signingKey, null);
        var signedRequest = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of(
                "signature-input", List.of(Signer.signatureInputHeader(result)),
                "signature", List.of(Signer.signatureHeader(result))
            ));

        var requirements = AcceptSignature.SignatureRequirements.builder()
            .component("@method")
            .algorithm(Algorithm.ED25519)
            .build();

        var options = Verifier.VerifyOptions.builder()
            .requirements(requirements)
            .rejectExpired(false)
            .build();

        assertThrows(HttpSigException.class,
            () -> Verifier.verify(signedRequest, (keyId, alg) -> verifyingKey, options, null));
    }

    @Test
    void backwardCompatRequiredComponents() throws Exception {
        byte[] secret = "backward-compat-test-secret-long!".getBytes();
        var signingKey = Keys.hmacSHA256Key("k", secret);
        var verifyingKey = Keys.hmacSHA256Key("k", secret);

        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());

        var params = SignatureParameters.builder()
            .component("@method")
            .keyId("k")
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1618884473L)
            .build();

        var result = Signer.sign(request, "sig1", params, signingKey, null);
        var signedRequest = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of(
                "signature-input", List.of(Signer.signatureInputHeader(result)),
                "signature", List.of(Signer.signatureHeader(result))
            ));

        // old-style requiredComponents still works
        var options = new Verifier.VerifyOptions(
            List.of(ComponentIdentifier.of("@method")),
            null, null, false, null, null, null
        );

        var verifyResult = Verifier.verify(signedRequest, (keyId, alg) -> verifyingKey, options, null);
        assertEquals("sig1", verifyResult.label());
    }
}
