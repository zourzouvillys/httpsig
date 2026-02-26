package com.zourzouvillys.httpsig.jdkhttp;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.List;

import com.zourzouvillys.httpsig.HttpMessage;

/**
 * Adapts a JDK {@link HttpResponse} to {@link HttpMessage} for verification.
 */
public final class JdkHttpResponseMessage implements HttpMessage {

    private final HttpResponse<?> response;

    public JdkHttpResponseMessage(HttpResponse<?> response) {
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
        return response.statusCode();
    }

    @Override
    public List<String> headerValues(String name) {
        return response.headers().allValues(name.toLowerCase());
    }
}
