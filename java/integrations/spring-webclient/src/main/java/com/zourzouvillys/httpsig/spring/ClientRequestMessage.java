package com.zourzouvillys.httpsig.spring;

import java.net.URI;
import java.util.List;

import com.zourzouvillys.httpsig.HttpMessage;

import org.springframework.web.reactive.function.client.ClientRequest;

/**
 * Adapts a Spring {@link ClientRequest} to {@link HttpMessage} for signing.
 */
final class ClientRequestMessage implements HttpMessage {

    private final ClientRequest request;

    ClientRequestMessage(ClientRequest request) {
        this.request = request;
    }

    @Override
    public boolean isRequest() {
        return true;
    }

    @Override
    public String method() {
        return request.method().name();
    }

    @Override
    public URI url() {
        return request.url();
    }

    @Override
    public int statusCode() {
        throw new UnsupportedOperationException("not a response");
    }

    @Override
    public List<String> headerValues(String name) {
        return request.headers().getOrDefault(name, List.of());
    }
}
