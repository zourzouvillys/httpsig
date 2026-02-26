package com.zourzouvillys.httpsig;

import java.util.Base64;

/**
 * Signs HTTP messages per RFC 9421.
 *
 * Usage:
 * <pre>
 *   var params = SignatureParameters.builder()
 *       .component("@method")
 *       .component("@authority")
 *       .component("content-type")
 *       .keyId("my-key")
 *       .created(Instant.now())
 *       .build();
 *
 *   var result = Signer.sign(request, "sig1", params, signingKey, null);
 *   // Add result headers to the outgoing message:
 *   //   Signature-Input: sig1=("@method" "@authority" "content-type");created=...;keyid="my-key"
 *   //   Signature: sig1=:base64signature:
 * </pre>
 */
public final class Signer {

    private Signer() {}

    /**
     * The result of a signing operation.
     *
     * @param label          the signature label (e.g. "sig1")
     * @param signatureInput the Signature-Input value for this label (the inner list + params)
     * @param signature      the raw signature bytes
     */
    public record SignResult(String label, String signatureInput, byte[] signature) {}

    /**
     * Sign an HTTP message.
     *
     * @param msg    the message to sign
     * @param label  the signature label
     * @param params what to sign and with what metadata
     * @param key    the signing key
     * @param reqMsg the related request (for response signatures, or null)
     * @return the signing result
     */
    public static SignResult sign(HttpMessage msg, String label, SignatureParameters params,
                                   SigningKey key, HttpMessage reqMsg) throws HttpSigException {
        var base = SignatureBase.build(msg, params, reqMsg);
        byte[] sig = key.sign(base.base());
        return new SignResult(label, base.signatureInput(), sig);
    }

    /**
     * Combine multiple sign results into a single Signature-Input header value.
     */
    public static String signatureInputHeader(SignResult... results) {
        var sb = new StringBuilder();
        for (int i = 0; i < results.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(results[i].label());
            sb.append('=');
            sb.append(results[i].signatureInput());
        }
        return sb.toString();
    }

    /**
     * Combine multiple sign results into a single Signature header value.
     */
    public static String signatureHeader(SignResult... results) {
        var sb = new StringBuilder();
        for (int i = 0; i < results.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(results[i].label());
            sb.append("=:");
            sb.append(Base64.getEncoder().encodeToString(results[i].signature()));
            sb.append(':');
        }
        return sb.toString();
    }
}
