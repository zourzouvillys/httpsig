package io.zrz.httpsig;

/**
 * Base exception for HTTP signature operations.
 */
public class HttpSigException extends Exception {

    public HttpSigException(String message) {
        super(message);
    }

    public HttpSigException(String message, Throwable cause) {
        super(message, cause);
    }
}
