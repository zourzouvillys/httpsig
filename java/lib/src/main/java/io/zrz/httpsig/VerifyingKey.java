package io.zrz.httpsig;

/**
 * A key that can verify signatures.
 */
public interface VerifyingKey {

    String keyId();

    Algorithm algorithm();

    boolean verify(byte[] data, byte[] signature) throws HttpSigException;
}
