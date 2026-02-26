package io.zrz.httpsig.okhttp;

import java.net.URI;
import java.util.List;

import io.zrz.httpsig.HttpMessage;

import okhttp3.Response;

/**
 * Adapts an OkHttp {@link Response} to {@link HttpMessage} for verification.
 */
public final class OkHttpResponseMessage implements HttpMessage {

    private final Response response;

    public OkHttpResponseMessage(Response response) {
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
        return response.code();
    }

    @Override
    public List<String> headerValues(String name) {
        return response.headers(name);
    }
}
