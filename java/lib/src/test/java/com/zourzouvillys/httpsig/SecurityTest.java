package com.zourzouvillys.httpsig;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Security regression tests for HTTP message signatures.
 *
 * These verify that the verifier actually enforces the guardrails that
 * prevent replay attacks, algorithm confusion, and untrusted metadata leaking.
 */
class SecurityTest {

    private static final byte[] SECRET = "test-secret-key-long-enough-for-hmac!".getBytes();
    private static final String KEY_ID = "test-key";

    private static Keys.HmacKey hmacKey() {
        return Keys.hmacSHA256Key(KEY_ID, SECRET);
    }

    /**
     * Helper: sign a minimal GET request with the given params, return the signed message.
     */
    private static HttpMessage signRequest(SignatureParameters params) throws HttpSigException {
        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());

        var result = Signer.sign(request, "sig1", params, hmacKey(), null);

        return RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of(
                "signature-input", List.of(Signer.signatureInputHeader(result)),
                "signature", List.of(Signer.signatureHeader(result))
            ));
    }

    // -----------------------------------------------------------------------
    // 1. Future-dated signature rejection
    // -----------------------------------------------------------------------

    @Test
    void futureDatedSignature_rejectedByTightClockSkew() throws Exception {
        Instant now = Instant.now();
        Instant oneHourFromNow = now.plusSeconds(3600);

        var params = SignatureParameters.builder()
            .component("@method")
            .keyId(KEY_ID)
            .algorithm(Algorithm.HMAC_SHA256)
            .created(oneHourFromNow)
            .build();

        var signedRequest = signRequest(params);

        // 30s skew tolerance should reject a signature created 1 hour in the future
        var tightOptions = new Verifier.VerifyOptions(
            null,
            null,
            Duration.ofSeconds(30),
            null,
            null,
            () -> now
        );

        var ex = assertThrows(HttpSigException.class,
            () -> Verifier.verify(signedRequest, (keyId, alg) -> hmacKey(), tightOptions, null));
        assertTrue(ex.getMessage().contains("future-dated"),
            "expected 'future-dated' in message but got: " + ex.getMessage());
    }

    @Test
    void futureDatedSignature_acceptedByLooseClockSkew() throws Exception {
        Instant now = Instant.now();
        Instant oneHourFromNow = now.plusSeconds(3600);

        var params = SignatureParameters.builder()
            .component("@method")
            .keyId(KEY_ID)
            .algorithm(Algorithm.HMAC_SHA256)
            .created(oneHourFromNow)
            .build();

        var signedRequest = signRequest(params);

        // 2 hour tolerance should accept a signature 1 hour in the future
        var looseOptions = new Verifier.VerifyOptions(
            null,
            null,
            Duration.ofHours(2),
            null,
            null,
            () -> now
        );

        var result = Verifier.verify(signedRequest, (keyId, alg) -> hmacKey(), looseOptions, null);
        assertEquals("sig1", result.label());
    }

    @Test
    void futureDatedSignature_acceptedWhenNoClockSkewConfigured() throws Exception {
        Instant now = Instant.now();
        Instant oneHourFromNow = now.plusSeconds(3600);

        var params = SignatureParameters.builder()
            .component("@method")
            .keyId(KEY_ID)
            .algorithm(Algorithm.HMAC_SHA256)
            .created(oneHourFromNow)
            .build();

        var signedRequest = signRequest(params);

        // null maxClockSkew means no future-date check at all
        var noSkewOptions = new Verifier.VerifyOptions(
            null,
            null,
            null,
            null,
            null,
            () -> now
        );

        var result = Verifier.verify(signedRequest, (keyId, alg) -> hmacKey(), noSkewOptions, null);
        assertEquals("sig1", result.label());
    }

    // -----------------------------------------------------------------------
    // 2. Algorithm mismatch rejection
    // -----------------------------------------------------------------------

    @Test
    void algorithmMismatch_signatureInputClaimsDifferentAlgorithm() throws Exception {
        // Sign with HMAC-SHA256 and include alg param in signature
        var params = SignatureParameters.builder()
            .component("@method")
            .keyId(KEY_ID)
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1618884473L)
            .build();

        var request = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of());

        var result = Signer.sign(request, "sig1", params, hmacKey(), null);
        String sigInputHeader = Signer.signatureInputHeader(result);
        String sigHeader = Signer.signatureHeader(result);

        // Tamper: replace alg="hmac-sha256" with alg="ed25519" in the signature-input
        String tamperedSigInput = sigInputHeader.replace("hmac-sha256", "ed25519");

        // Sanity: the replacement actually happened
        assertTrue(tamperedSigInput.contains("ed25519"),
            "tampered input should contain ed25519");
        assertFalse(tamperedSigInput.contains("hmac-sha256"),
            "tampered input should not contain hmac-sha256");

        var signedRequest = RawMessage.request("GET", URI.create("https://example.com/"),
            Map.of(
                "signature-input", List.of(tamperedSigInput),
                "signature", List.of(sigHeader)
            ));

        // The key provider returns the real HMAC key. The verifier should
        // reject because the header claims ed25519 but the key is hmac-sha256.
        var ex = assertThrows(HttpSigException.class,
            () -> Verifier.verify(signedRequest, (keyId, alg) -> hmacKey(),
                Verifier.VerifyOptions.defaults(), null));
        assertTrue(ex.getMessage().contains("algorithm mismatch"),
            "expected 'algorithm mismatch' in message but got: " + ex.getMessage());
    }

    // -----------------------------------------------------------------------
    // 3. VerifyResult returns the key's algorithm, not untrusted header alg
    // -----------------------------------------------------------------------

    @Test
    void verifyResult_reportsKeyAlgorithm_notHeaderAlgorithm() throws Exception {
        var params = SignatureParameters.builder()
            .component("@method")
            .keyId(KEY_ID)
            .algorithm(Algorithm.HMAC_SHA256)
            .createdEpoch(1618884473L)
            .build();

        var signedRequest = signRequest(params);

        var result = Verifier.verify(signedRequest, (keyId, alg) -> hmacKey(),
            Verifier.VerifyOptions.defaults(), null);

        // The result's algorithm must come from the key, not from parsing the header.
        assertEquals(Algorithm.HMAC_SHA256, result.algorithm());
        assertEquals(hmacKey().algorithm(), result.algorithm());
    }

    @Test
    void verifyResult_reportsKeyAlgorithm_evenWhenHeaderOmitsAlg() throws Exception {
        // Sign WITHOUT setting algorithm in params (no alg= in signature-input)
        var params = SignatureParameters.builder()
            .component("@method")
            .keyId(KEY_ID)
            .createdEpoch(1618884473L)
            .build();

        var signedRequest = signRequest(params);

        var result = Verifier.verify(signedRequest, (keyId, alg) -> hmacKey(),
            Verifier.VerifyOptions.defaults(), null);

        // Even with no alg in the header, result.algorithm() should be the key's algorithm.
        assertEquals(Algorithm.HMAC_SHA256, result.algorithm());
    }
}
