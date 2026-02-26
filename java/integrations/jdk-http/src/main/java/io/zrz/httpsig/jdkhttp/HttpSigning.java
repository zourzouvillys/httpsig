package io.zrz.httpsig.jdkhttp;

import java.net.URI;
import java.net.http.HttpRequest;

import io.zrz.httpsig.HttpSigException;
import io.zrz.httpsig.SignatureParameters;
import io.zrz.httpsig.Signer;
import io.zrz.httpsig.SigningKey;

/**
 * Utility for signing JDK {@link HttpRequest}s with HTTP Message Signatures (RFC 9421).
 *
 * Because HttpRequest is immutable once built, you sign via the builder:
 * <pre>
 *   var builder = HttpRequest.newBuilder()
 *       .uri(URI.create("https://example.com/api"))
 *       .header("Content-Type", "application/json")
 *       .GET();
 *
 *   HttpSigning.sign(builder, "sig1", params, signingKey);
 *
 *   var request = builder.build();
 * </pre>
 *
 * The sign method builds the request internally to read headers and URI,
 * computes the signature, then adds the Signature-Input and Signature headers
 * to the same builder.
 */
public final class HttpSigning {

    private HttpSigning() {}

    /**
     * Sign a request builder. Adds Signature-Input and Signature headers.
     *
     * @param builder the request builder (will be mutated with signature headers)
     * @param label   the signature label (e.g. "sig1")
     * @param params  what to sign and with what metadata
     * @param key     the signing key
     */
    public static void sign(HttpRequest.Builder builder, String label,
                            SignatureParameters params, SigningKey key) throws HttpSigException {
        // build a snapshot to read method/uri/headers
        HttpRequest snapshot = builder.build();
        var msg = new JdkHttpRequestMessage(
            snapshot.method(),
            snapshot.uri(),
            snapshot.headers()
        );

        Signer.SignResult result = Signer.sign(msg, label, params, key, null);

        // re-set the original properties and add signature headers.
        // HttpRequest.Builder doesn't have a "copy" method, but we can re-derive
        // from the snapshot. However, the caller still holds the builder reference,
        // so we just add headers to it. The snapshot.build() consumed nothing,
        // the builder is still usable.
        builder.header("Signature-Input", Signer.signatureInputHeader(result));
        builder.header("Signature", Signer.signatureHeader(result));
    }

    /**
     * Sign with the default label "sig1".
     */
    public static void sign(HttpRequest.Builder builder,
                            SignatureParameters params, SigningKey key) throws HttpSigException {
        sign(builder, "sig1", params, key);
    }
}
