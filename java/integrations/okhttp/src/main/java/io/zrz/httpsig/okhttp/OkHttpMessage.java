package io.zrz.httpsig.okhttp;

import java.net.URI;
import java.util.List;

import io.zrz.httpsig.HttpMessage;

import okhttp3.Request;

/**
 * Adapts an OkHttp {@link Request} to {@link HttpMessage} for signing.
 */
final class OkHttpMessage implements HttpMessage {

    private final Request request;

    OkHttpMessage(Request request) {
        this.request = request;
    }

    @Override
    public boolean isRequest() {
        return true;
    }

    @Override
    public String method() {
        return request.method();
    }

    @Override
    public URI url() {
        return request.url().uri();
    }

    @Override
    public int statusCode() {
        throw new UnsupportedOperationException("not a response");
    }

    @Override
    public List<String> headerValues(String name) {
        return request.headers(name);
    }
}
