package com.zourzouvillys.httpsig.spring;

import java.net.URI;
import java.util.List;

import com.zourzouvillys.httpsig.HttpMessage;

import org.springframework.web.reactive.function.client.ClientResponse;

/**
 * Adapts a Spring {@link ClientResponse} to {@link HttpMessage} for verification.
 */
public final class ClientResponseMessage implements HttpMessage {

    private final ClientResponse response;

    public ClientResponseMessage(ClientResponse response) {
        this.response = response;
    }

    @Override
    public boolean isRequest() {
        return false;
    }

    @Override
    public String method() {
        throw new UnsupportedOperationException("not a request");
    }

    @Override
    public URI url() {
        throw new UnsupportedOperationException("not a request");
    }

    @Override
    public int statusCode() {
        return response.statusCode().value();
    }

    @Override
    public List<String> headerValues(String name) {
        return response.headers().asHttpHeaders().getOrDefault(name, List.of());
    }
}
