package com.zourzouvillys.httpsig.okhttp;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.zourzouvillys.httpsig.Algorithm;
import com.zourzouvillys.httpsig.Keys;
import com.zourzouvillys.httpsig.RawMessage;
import com.zourzouvillys.httpsig.SignatureParameters;
import com.zourzouvillys.httpsig.Verifier;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;

class SigningInterceptorTest {

    private MockWebServer server;

    @BeforeEach
    void setUp() throws Exception {
        server = new MockWebServer();
        server.start();
    }

    @AfterEach
    void tearDown() throws Exception {
        server.shutdown();
    }

    @Test
    void interceptorSignsAndVerifierAccepts() throws Exception {
        byte[] secret = "test-secret-long-enough-for-hmac!".getBytes();
        var signingKey = Keys.hmacSHA256Key("test-key", secret);
        var verifyingKey = Keys.hmacSHA256Key("test-key", secret);

        var interceptor = new SigningInterceptor(
            signingKey,
            req -> SignatureParameters.builder()
                .component("@method")
                .component("@authority")
                .component("@path")
                .keyId("test-key")
                .algorithm(Algorithm.HMAC_SHA256)
                .createdEpoch(1618884473L)
                .build()
        );

        var client = new OkHttpClient.Builder()
            .addInterceptor(interceptor)
            .build();

        server.enqueue(new MockResponse().setBody("ok"));

        var request = new Request.Builder()
            .url(server.url("/api/resource"))
            .get()
            .build();

        try (var response = client.newCall(request).execute()) {
            assertEquals(200, response.code());
        }

        RecordedRequest recorded = server.takeRequest();

        // the recorded request should have signature headers
        String sigInput = recorded.getHeader("Signature-Input");
        String sig = recorded.getHeader("Signature");
        assertNotNull(sigInput, "Signature-Input header should be present");
        assertNotNull(sig, "Signature header should be present");

        // reconstruct as RawMessage and verify the signature
        var uri = recorded.getRequestUrl().uri();
        var rawMsg = RawMessage.request(
            recorded.getMethod(),
            uri,
            Map.of(
                "signature-input", List.of(sigInput),
                "signature", List.of(sig)
            )
        );

        var result = Verifier.verify(rawMsg, (keyId, alg) -> verifyingKey,
            Verifier.VerifyOptions.defaults(), null);

        assertEquals("sig1", result.label());
        assertEquals("test-key", result.keyId());
        assertEquals(Algorithm.HMAC_SHA256, result.algorithm());
    }

    @Test
    void customLabelIsUsed() throws Exception {
        byte[] secret = "another-secret-long-enough!!!!!!".getBytes();
        var signingKey = Keys.hmacSHA256Key("k2", secret);
        var verifyingKey = Keys.hmacSHA256Key("k2", secret);

        var interceptor = new SigningInterceptor(
            signingKey,
            "my-sig",
            req -> SignatureParameters.builder()
                .component("@method")
                .keyId("k2")
                .algorithm(Algorithm.HMAC_SHA256)
                .createdEpoch(100L)
                .build()
        );

        var client = new OkHttpClient.Builder()
            .addInterceptor(interceptor)
            .build();

        server.enqueue(new MockResponse().setBody("ok"));

        var request = new Request.Builder()
            .url(server.url("/"))
            .get()
            .build();

        try (var response = client.newCall(request).execute()) {
            assertEquals(200, response.code());
        }

        RecordedRequest recorded = server.takeRequest();
        String sigInput = recorded.getHeader("Signature-Input");
        assertNotNull(sigInput);
        assertTrue(sigInput.startsWith("my-sig="), "should use custom label, got: " + sigInput);

        // verify it too
        var rawMsg = RawMessage.request(
            recorded.getMethod(),
            recorded.getRequestUrl().uri(),
            Map.of(
                "signature-input", List.of(sigInput),
                "signature", List.of(recorded.getHeader("Signature"))
            )
        );

        var opts = new Verifier.VerifyOptions(null, null, null, null, "my-sig", null);
        var result = Verifier.verify(rawMsg, (keyId, alg) -> verifyingKey, opts, null);
        assertEquals("my-sig", result.label());
    }
}
