package io.zrz.httpsig;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Simple {@link HttpMessage} implementation backed by plain fields.
 * Useful for testing and for wrapping raw HTTP data.
 */
public final class RawMessage implements HttpMessage {

    private final boolean isRequest;
    private final String method;
    private final URI url;
    private final int statusCode;
    private final Map<String, List<String>> headers;

    private RawMessage(boolean isRequest, String method, URI url, int statusCode,
                       Map<String, List<String>> headers) {
        this.isRequest = isRequest;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        // store in a case-insensitive map
        TreeMap<String, List<String>> ci = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            headers.forEach((k, v) -> ci.put(k, List.copyOf(v)));
        }
        this.headers = ci;
    }

    /** Create a request message. */
    public static RawMessage request(String method, URI url, Map<String, List<String>> headers) {
        return new RawMessage(true, method, url, 0, headers);
    }

    /** Create a response message. */
    public static RawMessage response(int statusCode, Map<String, List<String>> headers) {
        return new RawMessage(false, null, null, statusCode, headers);
    }

    @Override
    public boolean isRequest() { return isRequest; }

    @Override
    public String method() { return method; }

    @Override
    public URI url() { return url; }

    @Override
    public int statusCode() { return statusCode; }

    @Override
    public List<String> headerValues(String name) {
        return headers.getOrDefault(name, List.of());
    }
}
