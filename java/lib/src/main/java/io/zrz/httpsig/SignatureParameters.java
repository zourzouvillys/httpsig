package io.zrz.httpsig;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Parameters that control signature creation: which components to sign,
 * which algorithm/key to advertise, and optional metadata like created/expires.
 *
 * Built via {@link #builder()}.
 */
public final class SignatureParameters {

    private final List<ComponentIdentifier> components;
    private final Algorithm algorithm;
    private final String keyId;
    private final Long created;
    private final Long expires;
    private final String nonce;
    private final String tag;

    private SignatureParameters(Builder b) {
        this.components = List.copyOf(b.components);
        this.algorithm = b.algorithm;
        this.keyId = b.keyId;
        this.created = b.created;
        this.expires = b.expires;
        this.nonce = b.nonce;
        this.tag = b.tag;
    }

    public List<ComponentIdentifier> components() { return components; }
    public Algorithm algorithm() { return algorithm; }
    public String keyId() { return keyId; }
    public Long created() { return created; }
    public Long expires() { return expires; }
    public String nonce() { return nonce; }
    public String tag() { return tag; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final List<ComponentIdentifier> components = new ArrayList<>();
        private Algorithm algorithm;
        private String keyId;
        private Long created;
        private Long expires;
        private String nonce;
        private String tag;

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

        public Builder algorithm(Algorithm algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder created(Instant created) {
            this.created = created.getEpochSecond();
            return this;
        }

        public Builder createdEpoch(long created) {
            this.created = created;
            return this;
        }

        public Builder expires(Instant expires) {
            this.expires = expires.getEpochSecond();
            return this;
        }

        public Builder expiresEpoch(long expires) {
            this.expires = expires;
            return this;
        }

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder tag(String tag) {
            this.tag = tag;
            return this;
        }

        public SignatureParameters build() {
            return new SignatureParameters(this);
        }
    }
}
