package io.zrz.httpsig.spring;

import java.util.function.Function;

import io.zrz.httpsig.HttpSigException;
import io.zrz.httpsig.SignatureParameters;
import io.zrz.httpsig.Signer;
import io.zrz.httpsig.SigningKey;

import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import reactor.core.publisher.Mono;

/**
 * Spring WebClient {@link ExchangeFilterFunction} that signs outgoing requests
 * with HTTP Message Signatures (RFC 9421).
 *
 * <pre>
 *   var filter = new SigningFilterFunction(
 *       signingKey,
 *       req -> SignatureParameters.builder()
 *           .component("@method")
 *           .component("@authority")
 *           .keyId("my-key")
 *           .created(Instant.now())
 *           .build()
 *   );
 *
 *   var client = WebClient.builder()
 *       .filter(filter)
 *       .build();
 * </pre>
 */
public final class SigningFilterFunction implements ExchangeFilterFunction {

    private final SigningKey key;
    private final String label;
    private final Function<ClientRequest, SignatureParameters> paramsFactory;

    /**
     * @param key           the signing key
     * @param paramsFactory produces {@link SignatureParameters} for each request
     */
    public SigningFilterFunction(SigningKey key,
                                 Function<ClientRequest, SignatureParameters> paramsFactory) {
        this(key, "sig1", paramsFactory);
    }

    /**
     * @param key           the signing key
     * @param label         the signature label (e.g. "sig1")
     * @param paramsFactory produces {@link SignatureParameters} for each request
     */
    public SigningFilterFunction(SigningKey key, String label,
                                 Function<ClientRequest, SignatureParameters> paramsFactory) {
        this.key = key;
        this.label = label;
        this.paramsFactory = paramsFactory;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        SignatureParameters params = paramsFactory.apply(request);
        var msg = new ClientRequestMessage(request);

        Signer.SignResult result;
        try {
            result = Signer.sign(msg, label, params, key, null);
        } catch (HttpSigException e) {
            return Mono.error(e);
        }

        ClientRequest signed = ClientRequest.from(request)
            .header("Signature-Input", Signer.signatureInputHeader(result))
            .header("Signature", Signer.signatureHeader(result))
            .build();

        return next.exchange(signed);
    }
}
