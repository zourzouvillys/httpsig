package io.zrz.httpsig.spring;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import io.zrz.httpsig.Algorithm;
import io.zrz.httpsig.Keys;
import io.zrz.httpsig.RawMessage;
import io.zrz.httpsig.SignatureParameters;
import io.zrz.httpsig.Verifier;

import reactor.core.publisher.Mono;

class SigningFilterFunctionTest {

    @Test
    void filterSignsRequestAndVerifierAccepts() throws Exception {
        byte[] secret = "test-secret-long-enough-for-hmac!".getBytes();
        var signingKey = Keys.hmacSHA256Key("test-key", secret);
        var verifyingKey = Keys.hmacSHA256Key("test-key", secret);

        var filter = new SigningFilterFunction(
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

        // capture the signed request that the filter passes downstream
        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        ExchangeFunction downstream = request -> {
            captured.set(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        };

        ClientRequest original = ClientRequest.create(HttpMethod.POST, URI.create("https://example.com/api/resource"))
            .header("Content-Type", "application/json")
            .build();

        filter.filter(original, downstream).block();

        ClientRequest signed = captured.get();
        assertNotNull(signed);

        List<String> sigInputValues = signed.headers().get("Signature-Input");
        List<String> sigValues = signed.headers().get("Signature");
        assertNotNull(sigInputValues);
        assertNotNull(sigValues);
        assertEquals(1, sigInputValues.size());
        assertEquals(1, sigValues.size());

        // verify via core library
        var rawMsg = RawMessage.request(
            signed.method().name(),
            signed.url(),
            Map.of(
                "content-type", List.of("application/json"),
                "signature-input", sigInputValues,
                "signature", sigValues
            )
        );

        var result = Verifier.verify(rawMsg, (keyId, alg) -> verifyingKey,
            Verifier.VerifyOptions.defaults(), null);

        assertEquals("sig1", result.label());
        assertEquals("test-key", result.keyId());
    }

    @Test
    void customLabelIsUsed() throws Exception {
        byte[] secret = "another-secret-long-enough!!!!!!".getBytes();
        var signingKey = Keys.hmacSHA256Key("k", secret);

        var filter = new SigningFilterFunction(
            signingKey,
            "custom",
            req -> SignatureParameters.builder()
                .component("@method")
                .keyId("k")
                .algorithm(Algorithm.HMAC_SHA256)
                .createdEpoch(100L)
                .build()
        );

        AtomicReference<ClientRequest> captured = new AtomicReference<>();
        ExchangeFunction downstream = request -> {
            captured.set(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK).build());
        };

        ClientRequest original = ClientRequest.create(HttpMethod.GET, URI.create("https://example.com/"))
            .build();

        filter.filter(original, downstream).block();

        ClientRequest signed = captured.get();
        String sigInput = signed.headers().getFirst("Signature-Input");
        assertNotNull(sigInput);
        assertTrue(sigInput.startsWith("custom="), "should use custom label, got: " + sigInput);
    }
}
