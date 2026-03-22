package io.zrz.httpsig;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Accept-Signature header support per RFC 9421 Section 5.
 *
 * Provides building and parsing of Accept-Signature headers, and a
 * {@link SignatureRequirements} type that can be used for both
 * verification filtering and signature negotiation.
 */
public final class AcceptSignature {

    private AcceptSignature() {}

    /**
     * Describes what a valid signature must look like.
     *
     * Used for:
     * <ul>
     *   <li>Verification filtering — the verifier uses it to decide if a signature is acceptable</li>
     *   <li>Accept-Signature building — serializes to an Accept-Signature header entry</li>
     *   <li>SignatureParameters conversion — converts to params for signing a matching request</li>
     * </ul>
     */
    public record SignatureRequirements(
        List<ComponentIdentifier> components,
        String keyId,
        Algorithm algorithm,
        String tag,
        boolean requireCreated,
        boolean requireExpires
    ) {
        public SignatureRequirements {
            components = List.copyOf(components);
        }

        public static Builder builder() {
            return new Builder();
        }

        /**
         * Convert these requirements to {@link SignatureParameters} suitable for signing.
         *
         * @param created epoch seconds for the created timestamp (or null to omit)
         * @param expires epoch seconds for the expires timestamp (or null to omit)
         * @param nonce   nonce value (or null to omit)
         */
        public SignatureParameters toSignatureParameters(Long created, Long expires, String nonce) {
            var b = SignatureParameters.builder()
                .components(components);
            if (keyId != null) b.keyId(keyId);
            if (algorithm != null) b.algorithm(algorithm);
            if (tag != null) b.tag(tag);
            if (created != null) b.createdEpoch(created);
            if (expires != null) b.expiresEpoch(expires);
            if (nonce != null) b.nonce(nonce);
            return b.build();
        }

        public static final class Builder {
            private final List<ComponentIdentifier> components = new ArrayList<>();
            private String keyId;
            private Algorithm algorithm;
            private String tag;
            private boolean requireCreated;
            private boolean requireExpires;

            private Builder() {}

            public Builder component(ComponentIdentifier c) {
                components.add(c);
                return this;
            }

            public Builder component(String name) {
                return component(ComponentIdentifier.of(name));
            }

            public Builder components(List<ComponentIdentifier> cs) {
                components.addAll(cs);
                return this;
            }

            public Builder keyId(String keyId) {
                this.keyId = keyId;
                return this;
            }

            public Builder algorithm(Algorithm algorithm) {
                this.algorithm = algorithm;
                return this;
            }

            public Builder tag(String tag) {
                this.tag = tag;
                return this;
            }

            public Builder requireCreated(boolean requireCreated) {
                this.requireCreated = requireCreated;
                return this;
            }

            public Builder requireExpires(boolean requireExpires) {
                this.requireExpires = requireExpires;
                return this;
            }

            public SignatureRequirements build() {
                return new SignatureRequirements(
                    components, keyId, algorithm, tag,
                    requireCreated, requireExpires
                );
            }
        }
    }

    /**
     * Build an Accept-Signature header value from a map of label to requirements.
     *
     * @param entries map of signature label to requirements
     * @return the serialized Accept-Signature header value
     */
    public static String build(Map<String, SignatureRequirements> entries) {
        var members = new ArrayList<SFV.DictMember>();
        for (var entry : entries.entrySet()) {
            members.add(toDictMember(entry.getKey(), entry.getValue()));
        }
        return SFV.serializeDictionary(members);
    }

    /**
     * Parse an Accept-Signature header value.
     *
     * @param headerValue the raw header value
     * @return map of signature label to requirements (preserving order)
     * @throws HttpSigException if the header is malformed
     */
    public static Map<String, SignatureRequirements> parse(String headerValue) throws HttpSigException {
        var dictMembers = SFV.parseDictionary(headerValue);
        var result = new LinkedHashMap<String, SignatureRequirements>();
        for (var member : dictMembers) {
            result.put(member.key(), fromDictMember(member));
        }
        return result;
    }

    private static SFV.DictMember toDictMember(String label, SignatureRequirements req) {
        // build inner list items from components
        var items = new ArrayList<SFV.Item>();
        for (var cid : req.components()) {
            var itemParams = new LinkedHashMap<String, Object>();
            itemParams.putAll(cid.params());
            items.add(new SFV.Item(cid.name(), itemParams.isEmpty() ? SFV.Params.EMPTY : new SFV.Params(itemParams)));
        }

        // build inner list params
        var listParams = new LinkedHashMap<String, Object>();
        if (req.keyId() != null) {
            listParams.put("keyid", req.keyId());
        }
        if (req.algorithm() != null) {
            listParams.put("alg", req.algorithm().value());
        }
        if (req.requireCreated()) {
            listParams.put("created", true);
        }
        if (req.requireExpires()) {
            listParams.put("expires", true);
        }
        if (req.tag() != null) {
            listParams.put("tag", req.tag());
        }

        var innerList = new SFV.InnerList(items, new SFV.Params(listParams));
        return new SFV.DictMember(label, innerList, SFV.Params.EMPTY);
    }

    private static SignatureRequirements fromDictMember(SFV.DictMember member) throws HttpSigException {
        if (!(member.value() instanceof SFV.InnerList innerList)) {
            throw new HttpSigException("Accept-Signature entry '" + member.key() + "' is not an inner list");
        }

        // extract components
        var components = new ArrayList<ComponentIdentifier>();
        for (var item : innerList.items()) {
            if (!(item.value() instanceof String name)) {
                throw new HttpSigException("component identifier must be a string");
            }
            Map<String, Object> paramMap = new LinkedHashMap<>(item.params().map());
            components.add(ComponentIdentifier.withParams(name, paramMap));
        }

        // extract params
        SFV.Params params = innerList.params();
        String keyId = params.get("keyid") instanceof String s ? s : null;
        String algStr = params.get("alg") instanceof String s ? s : null;
        Algorithm algorithm = algStr != null ? Algorithm.fromValue(algStr) : null;
        String tag = params.get("tag") instanceof String s ? s : null;
        boolean requireCreated = Boolean.TRUE.equals(params.get("created"));
        boolean requireExpires = Boolean.TRUE.equals(params.get("expires"));

        return new SignatureRequirements(
            components, keyId, algorithm, tag,
            requireCreated, requireExpires
        );
    }
}
