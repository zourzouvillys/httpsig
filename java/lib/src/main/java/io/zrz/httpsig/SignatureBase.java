package io.zrz.httpsig;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Constructs the signature base string per RFC 9421 Section 2.5.
 *
 * The signature base is a deterministic byte sequence derived from the
 * HTTP message, the covered components, and the signature parameters.
 * It's the input to the signing/verification algorithm.
 *
 *   "\"@method\": GET\n"
 *   "\"@authority\": example.com\n"
 *   "\"@signature-params\": (\"@method\" \"@authority\");created=1618884473;keyid=\"test-key\""
 */
final class SignatureBase {

    private SignatureBase() {}

    record Result(byte[] base, String signatureInput) {}

    /**
     * Build the signature base for signing. The signature-input string
     * is computed from the parameters.
     */
    static Result build(HttpMessage msg, SignatureParameters params, HttpMessage reqMsg)
            throws HttpSigException {
        var components = params.components();
        validateNoDuplicates(components);
        String sigInput = buildSignatureInput(params);
        byte[] base = buildBase(components, sigInput, msg, reqMsg);
        return new Result(base, sigInput);
    }

    /**
     * Build the signature base for verification. The signature-input string
     * is the exact value from the Signature-Input header, preserving the
     * original parameter ordering.
     */
    static byte[] buildForVerification(List<ComponentIdentifier> components, String signatureInput,
                                        HttpMessage msg, HttpMessage reqMsg) throws HttpSigException {
        validateNoDuplicates(components);
        return buildBase(components, signatureInput, msg, reqMsg);
    }

    private static byte[] buildBase(List<ComponentIdentifier> components, String signatureInput,
                                     HttpMessage msg, HttpMessage reqMsg) throws HttpSigException {
        var sb = new StringBuilder();
        for (var cid : components) {
            String value = Components.extract(cid, msg, reqMsg);
            sb.append(SFV.serializeComponentId(cid));
            sb.append(": ");
            sb.append(value);
            sb.append('\n');
        }
        sb.append("\"@signature-params\": ");
        sb.append(signatureInput);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Build the signature-input value: the serialized inner list of components
     * followed by the signature metadata parameters.
     */
    static String buildSignatureInput(SignatureParameters params) {
        var sfvParams = buildSFVParams(params);
        return SFV.serializeSignatureParams(params.components(), sfvParams);
    }

    /**
     * Build SFV params in canonical order: created, expires, keyid, alg, nonce, tag.
     */
    private static SFV.Params buildSFVParams(SignatureParameters params) {
        Map<String, Object> map = new LinkedHashMap<>();
        if (params.created() != null) {
            map.put("created", params.created());
        }
        if (params.expires() != null) {
            map.put("expires", params.expires());
        }
        if (params.keyId() != null) {
            map.put("keyid", params.keyId());
        }
        if (params.algorithm() != null) {
            map.put("alg", params.algorithm().value());
        }
        if (params.nonce() != null) {
            map.put("nonce", params.nonce());
        }
        if (params.tag() != null) {
            map.put("tag", params.tag());
        }
        return new SFV.Params(map);
    }

    private static void validateNoDuplicates(List<ComponentIdentifier> components)
            throws HttpSigException {
        var seen = new HashSet<String>();
        for (var cid : components) {
            String serialized = SFV.serializeComponentId(cid);
            if (!seen.add(serialized)) {
                throw new HttpSigException("duplicate component in signature: " + serialized);
            }
        }
    }
}
