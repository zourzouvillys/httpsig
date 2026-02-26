package io.zrz.httpsig;

/**
 * A key that can produce signatures.
 */
public interface SigningKey {

    String keyId();

    Algorithm algorithm();

    byte[] sign(byte[] data) throws HttpSigException;
}
