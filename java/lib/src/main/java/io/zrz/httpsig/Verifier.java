package io.zrz.httpsig;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Verifies HTTP message signatures per RFC 9421.
 *
 * Parses the Signature-Input and Signature headers, reconstructs the
 * signature base, and verifies using the key provided by a {@link KeyProvider}.
 */
public final class Verifier {

    private Verifier() {}

    /**
     * Options controlling verification behavior.
     *
     * @param requiredComponents components that must be covered by the signature (or null/empty to skip)
     * @param maxAge             reject signatures older than this (based on created, or null to skip)
     * @param maxClockSkew       reject signatures with created more than this far in the future (or null to skip)
     * @param rejectExpired      reject signatures past their expires time (defaults to true, set false to opt out)
     * @param requiredLabel      if set, only verify the signature with this specific label
     * @param now                clock source for age/expiry checks
     */
    public record VerifyOptions(
        List<ComponentIdentifier> requiredComponents,
        Duration maxAge,
        Duration maxClockSkew,
        Boolean rejectExpired,
        String requiredLabel,
        Supplier<Instant> now
    ) {
        public VerifyOptions {
            if (now == null) now = Instant::now;
        }

        public static VerifyOptions defaults() {
            return new VerifyOptions(null, null, null, true, null, null);
        }
    }

    /**
     * The result of a successful verification.
     */
    public record VerifyResult(
        String label,
        String keyId,
        Algorithm algorithm,
        List<ComponentIdentifier> components,
        Long created,
        Long expires
    ) {}

    /**
     * Verify signatures on an HTTP message.
     *
     * @param msg      the message with Signature and Signature-Input headers
     * @param provider resolves verifying keys
     * @param options  verification options
     * @param reqMsg   the related request (for response signatures, or null)
     * @return the first successfully verified result
     * @throws HttpSigException if no signature verifies
     */
    public static VerifyResult verify(HttpMessage msg, KeyProvider provider,
                                       VerifyOptions options, HttpMessage reqMsg)
            throws HttpSigException {

        // parse Signature-Input header
        List<String> sigInputHeaders = msg.headerValues("signature-input");
        if (sigInputHeaders.isEmpty()) {
            throw new HttpSigException("no Signature-Input header found");
        }
        String sigInputCombined = String.join(", ", sigInputHeaders);
        var sigInputEntries = SFV.parseDictionary(sigInputCombined);

        // parse Signature header
        List<String> sigHeaders = msg.headerValues("signature");
        if (sigHeaders.isEmpty()) {
            throw new HttpSigException("no Signature header found");
        }
        String sigCombined = String.join(", ", sigHeaders);
        var sigEntries = SFV.parseDictionary(sigCombined);

        // index signatures by label
        Map<String, byte[]> signatures = new LinkedHashMap<>();
        for (var entry : sigEntries) {
            Object val = entry.value();
            byte[] sigBytes;
            if (val instanceof SFV.Item item && item.value() instanceof byte[] b) {
                sigBytes = b;
            } else {
                continue; // skip malformed entries
            }
            signatures.put(entry.key(), sigBytes);
        }

        // try each signature-input entry
        List<String> errors = new ArrayList<>();
        for (var entry : sigInputEntries) {
            String label = entry.key();

            // if a specific label is required, skip others
            if (options.requiredLabel() != null && !options.requiredLabel().equals(label)) {
                continue;
            }

            try {
                var result = verifySingle(label, entry, signatures, msg, provider, options, reqMsg);
                return result;
            } catch (HttpSigException e) {
                errors.add(label + ": " + e.getMessage());
            }
        }

        throw new HttpSigException("no signature verified: " + String.join("; ", errors));
    }

    private static VerifyResult verifySingle(
            String label,
            SFV.DictMember sigInputEntry,
            Map<String, byte[]> signatures,
            HttpMessage msg,
            KeyProvider provider,
            VerifyOptions options,
            HttpMessage reqMsg
    ) throws HttpSigException {

        byte[] sigBytes = signatures.get(label);
        if (sigBytes == null) {
            throw new HttpSigException("no matching Signature entry for label '" + label + "'");
        }

        // the value should be an InnerList (the component list)
        if (!(sigInputEntry.value() instanceof SFV.InnerList innerList)) {
            throw new HttpSigException("signature-input for '" + label + "' is not an inner list");
        }

        // extract components from the inner list
        var components = new ArrayList<ComponentIdentifier>();
        for (var item : innerList.items()) {
            if (!(item.value() instanceof String name)) {
                throw new HttpSigException("component identifier must be a string");
            }
            Map<String, Object> paramMap = new LinkedHashMap<>(item.params().map());
            components.add(ComponentIdentifier.withParams(name, paramMap));
        }

        // extract signature metadata from the inner list's params
        SFV.Params metaParams = innerList.params();

        Long created = toLong(metaParams.get("created"));
        Long expires = toLong(metaParams.get("expires"));
        String keyId = metaParams.get("keyid") instanceof String s ? s : null;
        String algStr = metaParams.get("alg") instanceof String s ? s : null;
        String nonce = metaParams.get("nonce") instanceof String s ? s : null;
        String tag = metaParams.get("tag") instanceof String s ? s : null;

        Algorithm algorithm = algStr != null ? Algorithm.fromValue(algStr) : null;

        // check required components
        if (options.requiredComponents() != null) {
            for (var req : options.requiredComponents()) {
                String reqSer = SFV.serializeComponentId(req);
                boolean found = components.stream()
                    .anyMatch(c -> SFV.serializeComponentId(c).equals(reqSer));
                if (!found) {
                    throw new HttpSigException("required component " + reqSer + " not covered");
                }
            }
        }

        // check age/expiry
        Instant now = options.now().get();
        if (options.maxAge() != null && created != null) {
            Instant createdTime = Instant.ofEpochSecond(created);
            if (now.isAfter(createdTime.plus(options.maxAge()))) {
                throw new HttpSigException("signature too old");
            }
        }
        if (options.maxClockSkew() != null && created != null) {
            Instant createdTime = Instant.ofEpochSecond(created);
            if (createdTime.isAfter(now.plus(options.maxClockSkew()))) {
                throw new HttpSigException("signature future-dated");
            }
        }
        if (!Boolean.FALSE.equals(options.rejectExpired()) && expires != null) {
            if (now.isAfter(Instant.ofEpochSecond(expires))) {
                throw new HttpSigException("signature expired");
            }
        }

        // resolve key
        VerifyingKey key = provider.resolve(keyId, algorithm);
        if (key == null) {
            throw new HttpSigException("no key found for keyId='" + keyId + "'");
        }

        // if algorithm was specified in the input, it must match the key
        if (algorithm != null && key.algorithm() != algorithm) {
            throw new HttpSigException("algorithm mismatch: input says " + algorithm
                + " but key uses " + key.algorithm());
        }

        // re-serialize the inner list to get the exact signature-input value.
        // this preserves the original parameter ordering from the header.
        String signatureInput = SFV.serializeInnerList(innerList);
        byte[] base = SignatureBase.buildForVerification(components, signatureInput, msg, reqMsg);

        // verify
        if (!key.verify(base, sigBytes)) {
            throw new HttpSigException("signature verification failed for label '" + label + "'");
        }

        return new VerifyResult(
            label,
            key.keyId(),
            key.algorithm(),
            List.copyOf(components),
            created,
            expires
        );
    }

    private static Long toLong(Object v) {
        if (v instanceof Long l) return l;
        if (v instanceof Integer i) return (long) i;
        return null;
    }
}
