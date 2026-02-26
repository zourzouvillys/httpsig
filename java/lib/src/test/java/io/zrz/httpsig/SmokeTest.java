package io.zrz.httpsig;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Quick smoke test for the core sign/verify round-trip.
 */
class SmokeTest {

    @Test
    void hmacSignAndVerify() throws Exception {
        byte[] secret = "super-secret-key-that-is-long-enough".getBytes();
        var signingKey = Keys.hmacSHA256Key("test-key", secret);
        var verifyingKey = Keys.hmacSHA256Key("test-key", secret);

        var request = RawMessage.request("POST", URI.create("https://example.com/api/resource"),
            Map.of(
                "content-type", List.of("application/json"),
                "content-length", List.of("42")
            ));

        var params = SignatureParameters.builder()
            .component("@method")
            .component("@authority")
            .component("content-type")
            .keyId("test-key")
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1618884473L)
            .build();

        // sign
        var result = Signer.sign(request, "sig1", params, signingKey, null);
        assertNotNull(result.signature());
        assertNotNull(result.signatureInput());

        String sigInputHeader = Signer.signatureInputHeader(result);
        String sigHeader = Signer.signatureHeader(result);

        // build a message that includes the signature headers for verification
        var signedRequest = RawMessage.request("POST", URI.create("https://example.com/api/resource"),
            Map.of(
                "content-type", List.of("application/json"),
                "content-length", List.of("42"),
                "signature-input", List.of(sigInputHeader),
                "signature", List.of(sigHeader)
            ));

        // verify
        var verifyResult = Verifier.verify(signedRequest, (keyId, alg) -> verifyingKey,
            Verifier.VerifyOptions.defaults(), null);

        assertEquals("sig1", verifyResult.label());
        assertEquals("test-key", verifyResult.keyId());
        assertEquals(Algorithm.HMAC_SHA256, verifyResult.algorithm());
        assertEquals(1618884473L, verifyResult.created());
    }

    @Test
    void signatureBaseFormat() throws Exception {
        var request = RawMessage.request("GET", URI.create("https://example.com/path?q=1"),
            Map.of("host", List.of("example.com")));

        var params = SignatureParameters.builder()
            .component("@method")
            .component("@path")
            .component("@query")
            .keyId("my-key")
            .createdEpoch(1000000L)
            .build();

        String sigInput = SignatureBase.buildSignatureInput(params);
        assertTrue(sigInput.startsWith("(\"@method\" \"@path\" \"@query\")"));
        assertTrue(sigInput.contains(";created=1000000"));
        assertTrue(sigInput.contains(";keyid=\"my-key\""));
    }

    @Test
    void sfvParseDictionary() throws Exception {
        String input = "sig1=(\"@method\" \"@authority\");created=1618884473;keyid=\"test-key\"";
        var members = SFV.parseDictionary(input);
        assertEquals(1, members.size());
        assertEquals("sig1", members.get(0).key());
    }

    @Test
    void contentDigestRoundTrip() throws Exception {
        byte[] body = "hello world".getBytes();
        String headerValue = ContentDigest.compute(body, ContentDigest.DigestAlgorithm.SHA_256);
        assertTrue(headerValue.startsWith("sha-256=:"));
        assertTrue(ContentDigest.verify(body, headerValue));
        assertFalse(ContentDigest.verify("wrong body".getBytes(), headerValue));
    }

    @Test
    void componentExtraction() throws Exception {
        var request = RawMessage.request("POST", URI.create("https://example.com:443/api?name=val"),
            Map.of("content-type", List.of("application/json")));

        assertEquals("POST", Components.extract(ComponentIdentifier.of("@method"), request, null));
        assertEquals("example.com", Components.extract(ComponentIdentifier.of("@authority"), request, null));
        assertEquals("https", Components.extract(ComponentIdentifier.of("@scheme"), request, null));
        assertEquals("/api", Components.extract(ComponentIdentifier.of("@path"), request, null));
        assertEquals("?name=val", Components.extract(ComponentIdentifier.of("@query"), request, null));
        assertEquals("val", Components.extract(ComponentIdentifier.queryParam("name"), request, null));
        assertEquals("application/json", Components.extract(ComponentIdentifier.of("content-type"), request, null));
    }

    @Test
    void duplicateComponentsRejected() {
        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());
        var params = SignatureParameters.builder()
            .component("@method")
            .component("@method")
            .keyId("k")
            .build();

        byte[] secret = "secret-key-for-testing-purposes!".getBytes();
        var key = Keys.hmacSHA256Key("k", secret);
        assertThrows(HttpSigException.class, () -> Signer.sign(request, "s", params, key, null));
    }

    @Test
    void responseSignature() throws Exception {
        byte[] secret = "response-secret-that-is-long-enough!".getBytes();
        var signingKey = Keys.hmacSHA256Key("resp-key", secret);
        var verifyingKey = Keys.hmacSHA256Key("resp-key", secret);

        var response = RawMessage.response(200,
            Map.of("content-type", List.of("application/json")));

        var params = SignatureParameters.builder()
            .component("@status")
            .component("content-type")
            .keyId("resp-key")
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1618884473L)
            .build();

        var result = Signer.sign(response, "sig1", params, signingKey, null);
        String sigInputHeader = Signer.signatureInputHeader(result);
        String sigHeader = Signer.signatureHeader(result);

        var signedResponse = RawMessage.response(200,
            Map.of(
                "content-type", List.of("application/json"),
                "signature-input", List.of(sigInputHeader),
                "signature", List.of(sigHeader)
            ));

        var verifyResult = Verifier.verify(signedResponse, (keyId, alg) -> verifyingKey,
            Verifier.VerifyOptions.defaults(), null);
        assertEquals("sig1", verifyResult.label());
        assertEquals(200, signedResponse.statusCode());
    }

    @Test
    void verifyOptionsMaxAge() throws Exception {
        byte[] secret = "max-age-test-secret-long-enough!".getBytes();
        var signingKey = Keys.hmacSHA256Key("k", secret);
        var verifyingKey = Keys.hmacSHA256Key("k", secret);

        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());

        // sign with a very old created time
        var params = SignatureParameters.builder()
            .component("@method")
            .keyId("k")
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1000000L)
            .build();

        var result = Signer.sign(request, "sig1", params, signingKey, null);
        var signedRequest = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of(
                "signature-input", List.of(Signer.signatureInputHeader(result)),
                "signature", List.of(Signer.signatureHeader(result))
            ));

        // verify with a short max age should fail
        var options = new Verifier.VerifyOptions(
            null,
            java.time.Duration.ofSeconds(60),
            null,
            null,
            null,
            null
        );
        assertThrows(HttpSigException.class,
            () -> Verifier.verify(signedRequest, (keyId, alg) -> verifyingKey, options, null));
    }

    @Test
    void multipleSignatures() throws Exception {
        byte[] secret1 = "first-secret-long-enough-for-hmac!".getBytes();
        byte[] secret2 = "second-secret-also-long-enough!!!".getBytes();
        var key1 = Keys.hmacSHA256Key("key1", secret1);
        var key2 = Keys.hmacSHA256Key("key2", secret2);

        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());

        var params1 = SignatureParameters.builder()
            .component("@method")
            .keyId("key1")
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1000L)
            .build();

        var params2 = SignatureParameters.builder()
            .component("@method")
            .component("@authority")
            .keyId("key2")
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(2000L)
            .build();

        var r1 = Signer.sign(request, "sig1", params1, key1, null);
        var r2 = Signer.sign(request, "sig2", params2, key2, null);

        String sigInputHeader = Signer.signatureInputHeader(r1, r2);
        String sigHeader = Signer.signatureHeader(r1, r2);

        var signedRequest = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of(
                "signature-input", List.of(sigInputHeader),
                "signature", List.of(sigHeader)
            ));

        // verify sig2 specifically
        var options = new Verifier.VerifyOptions(null, null, null, null, "sig2", null);
        var verifyResult = Verifier.verify(signedRequest, (keyId, alg) -> {
            if ("key2".equals(keyId)) return key2;
            return null;
        }, options, null);
        assertEquals("sig2", verifyResult.label());
        assertEquals("key2", verifyResult.keyId());
    }
}
