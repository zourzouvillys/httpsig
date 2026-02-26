package com.zourzouvillys.httpsig.jdkhttp;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.List;

import com.zourzouvillys.httpsig.HttpMessage;

/**
 * Adapts a JDK {@link HttpRequest} to {@link HttpMessage} for signing.
 *
 * Since JDK's HttpRequest is immutable once built, this adapter works with
 * the request as-is. Use {@link HttpSigning#sign} to produce signature headers
 * from an HttpRequest.Builder before building.
 */
final class JdkHttpRequestMessage implements HttpMessage {

    private final String method;
    private final URI uri;
    private final java.net.http.HttpHeaders headers;

    JdkHttpRequestMessage(String method, URI uri, java.net.http.HttpHeaders headers) {
        this.method = method;
        this.uri = uri;
        this.headers = headers;
    }

    @Override
    public boolean isRequest() {
        return true;
    }

    @Override
    public String method() {
        return method;
    }

    @Override
    public URI url() {
        return uri;
    }

    @Override
    public int statusCode() {
        throw new UnsupportedOperationException("not a response");
    }

    @Override
    public List<String> headerValues(String name) {
        return headers.allValues(name.toLowerCase());
    }
}
