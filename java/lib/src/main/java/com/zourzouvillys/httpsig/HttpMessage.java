package com.zourzouvillys.httpsig;

import java.net.URI;
import java.util.List;

/**
 * Abstraction over an HTTP message (request or response) for signature operations.
 *
 * Implementations wrap whatever HTTP library the caller is using.
 */
public interface HttpMessage {

    /** True for requests, false for responses. */
    boolean isRequest();

    /** HTTP method (uppercase). Only meaningful for requests. */
    String method();

    /** Full request URI. Only meaningful for requests. */
    URI url();

    /** Status code. Only meaningful for responses. */
    int statusCode();

    /** All values for the given header name (case-insensitive). Empty list if absent. */
    List<String> headerValues(String name);
}
