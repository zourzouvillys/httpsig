---
sidebar_position: 6
---

# Security Architecture

Security considerations for HTTP message signatures: request-response binding, cryptographic attacks on signature chaining, behavior through intermediaries, and high-throughput signing with KMS-backed keys.

This is a companion to [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) (HTTP Message Signatures), not a replacement. Readers should be familiar with the base specification.

## Request-Response Binding

### The Problem

When a server signs a response, a client receiving that response needs assurance that it was generated in reply to the specific request the client sent, not replayed from a different request, and not grafted onto a different context by an intermediary or attacker.

Without explicit binding, a signed response is a free-floating assertion: "this body has this content." An attacker who observes (or causes) two requests to the same endpoint could swap the signed responses between them.

### The Mechanism: The `req` Parameter

RFC 9421 Section 2.4 defines the `req` parameter on component identifiers. When signing a response, the server can include components drawn from the originating request rather than the response itself.

```
Signature-Input: sig1=("@status" "content-digest"
    "@method";req "@path";req "content-digest";req)
    ;created=1618884479;keyid="server-key-1"
```

Here the response signature covers:

- `@status` -- the response status code
- `content-digest` -- the response body hash
- `@method;req` -- the request method (e.g., POST)
- `@path;req` -- the request path
- `content-digest;req` -- the request body hash

The resulting signature base interleaves response and request components:

```
"@status": 200
"content-digest": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
"@method";req: POST
"@path";req: /api/resource
"content-digest";req: sha-256=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+Tg=:
"@signature-params": ("@status" "content-digest" "@method";req "@path";req
    "content-digest";req);created=1618884479;keyid="server-key-1"
```

The response is now cryptographically bound to the request's method, path, and body content. It cannot be replayed as a response to a different request.

### Binding to the Request Signature Itself

The strongest form of binding is to include both the client's request signature and its signature parameters as covered components in the response signature. Since `Signature` and `Signature-Input` are both Dictionary structured fields, the `key` parameter selects a specific entry by its label:

```
Signature-Input: resp=("@status" "content-digest"
    "signature";req;key="sig1" "signature-input";req;key="sig1")
    ;created=1618884479;keyid="server-key-1"
```

This means the response signature covers:

- `"signature";req;key="sig1"` -- the raw bytes of the client's `sig1` signature value. If the request had been different (or unsigned), `sig1` would have a different value, and the response signature would not verify.
- `"signature-input";req;key="sig1"` -- the client's signature parameters (covered components, `created`, `keyid`, etc.). This prevents an attacker from swapping the client's `Signature-Input` while keeping the same signature bytes, which matters for defending against [key substitution attacks (DSKS)](#key-substitution-attacks-dsks-on-signature-chaining). Without this, an attacker who can construct a different key that validates the same signature bytes (possible with ECDSA) could rewrite the `Signature-Input` to claim different covered components or a different `keyid`, and the response signature would still verify. Covering the `Signature-Input` locks down both the signature value and the metadata describing what it covers.

Together, these create a cryptographic chain: client signs request, server signs response covering both the request signature and its parameters, the client can verify the chain end-to-end.

See the [Signing Responses](/guides/signing-responses) guide for implementation examples in all five languages.

### When the Client Does Not Sign Requests

If the client does not produce a request signature, the server cannot use signature chaining. In this case, the server should at minimum cover:

- `@method;req` -- to bind to the HTTP method
- `@target-uri;req` or `@path;req` + `@authority;req` -- to bind to the target
- `content-digest;req` -- to bind to the request body (if present)
- A client-generated nonce header (e.g., `x-request-id;req`) -- to bind to a specific request instance

This provides weaker guarantees. The server is asserting "I saw a request with these properties," but there is no proof that the client actually sent it, only that something matching those properties reached the server.

**Recommendation:** For applications requiring strong request-response binding, clients SHOULD sign requests.

## Key Substitution Attacks (DSKS) on Signature Chaining

### The Attack

When a response signature covers a request signature value (the chaining pattern above), a subtle cryptographic attack applies: Duplicate-Signature Key Selection (DSKS), also called key substitution.

For ECDSA (and some other schemes), given a valid signature `(r, s)` over message `M` under public key `K`, it is possible to construct a different public key `K'` such that `(r, s)` also validates against `K'`, potentially over a different message `M'`.

This means that covering only the raw signature bytes is not sufficient to prove that a specific client signed specific content. An attacker could construct a key that makes the same signature bytes appear to validate a different request.

### Mitigations

RFC 9421 Section 7.3.4 (Key Specification Mixup) addresses this class of attack. The following mitigations apply:

**1. The verifier must pin the expected client key.**

When verifying the response, the client already knows its own public key. The verification procedure is:

1. Verify the request signature `sig1` against the known client public key.
2. Verify the response signature `resp` against the known server public key, confirming that `"signature";req;key="sig1"` was covered.
3. Confirm that the covered signature value matches the `sig1` value the client produced.

Because the client verifies `sig1` against its own key (which it controls), DSKS is neutralized. An attacker cannot substitute a different key without the client noticing.

**2. The signature metadata is inherently covered.**

RFC 9421's signature base always includes `@signature-params` as the final line, which contains the full list of covered components including their parameters (such as `key="sig1"`). The `keyid` and `alg` parameters in the request's `Signature-Input` are not directly signed by the response, but they don't need to be. The client verifies the request signature independently against its own known key material.

**3. Application-level key binding.**

The application profile MUST define how verifiers resolve keys. The `keyid` parameter should map to a specific, pre-registered public key. Verifiers MUST NOT accept arbitrary keys presented alongside signatures. They must resolve keys through a trusted channel (JWKS endpoint, pre-shared configuration, etc.).

### Summary

DSKS is a real concern when signature values are used as inputs to other signatures. The defense is straightforward: every signature in the chain must be verified against a pinned, expected key, not against an attacker-controlled key. The cryptographic chain is only as strong as the key resolution at each link.

## Behavior Through Intermediaries

### How Signatures Survive Proxies

RFC 9421 uses Dictionary structured fields for both `Signature` and `Signature-Input`. This is deliberate: it allows multiple independent signatures to coexist on a single message without interfering with each other.

A message with two signatures looks like:

```
Signature-Input: sig1=("@method" "@target-uri" "content-digest")
    ;keyid="client-key";created=1618884475,
    sig2=("@method" "@target-uri" "content-digest"
    "x-proxy-header" "signature";key="sig1")
    ;keyid="proxy-key";created=1618884476
Signature: sig1=:BASE64_CLIENT_SIG:, sig2=:BASE64_PROXY_SIG:
```

The critical property: adding `sig2` does not modify `sig1`. The proxy appends a new dictionary member to each header. The client's original signature value and input parameters are untouched.

### The `key` Parameter on Dictionary Fields

When a component identifier uses `key` to select a dictionary member, it extracts only that member's value from the dictionary, ignoring all other members. So when the server covers:

```
"signature";req;key="sig1"
```

It gets the client's original signature bytes, regardless of how many other signatures a proxy may have added to the `Signature` header.

### What Proxies Must and Must Not Do

For end-to-end signature chaining to work:

**Proxies MUST:**

- Preserve existing `Signature` and `Signature-Input` dictionary members when adding their own signatures.
- Add new members (e.g., `sig2`) rather than replacing existing ones.
- Only add headers, not mutate headers that are covered by existing signatures.

**Proxies MUST NOT:**

- Strip or replace existing signature dictionary members.
- Modify header values that are covered by an upstream signature (this will break that signature).
- Rewrite the `Signature-Input` members of other signers.

If a proxy strips signatures, the chain is broken. The server binds to the proxy's signature, and the client has no way to verify a chain back to its own request. This may be acceptable in architectures where the proxy is an explicit trust boundary (analogous to TLS termination), but it must be a deliberate architectural decision, not an accident.

See the [Proxy Forwarding](/guides/proxy-forwarding) guide for implementation details.

### Practical Considerations

In practice, many HTTP intermediaries (CDNs, load balancers, API gateways) do not understand RFC 9421 signatures and may strip unfamiliar headers, reorder headers, or normalize values. Applications deploying signature chaining through intermediaries should:

- Test that signatures survive transit through every hop.
- Consider using the `bs` (binary sequence) parameter for fields whose values might be normalized.
- Use [Content-Digest](/concepts/content-digest) (RFC 9530) to protect body integrity rather than covering the body directly, since intermediaries may re-encode transfer encodings.
- Document which intermediaries are trust boundaries and which must be transparent to signatures.

## High-Throughput Signing with KMS-Backed Keys

### The Problem

Cloud KMS (AWS KMS, GCP Cloud KMS, Azure Key Vault) provides strong security properties: keys never leave HSM hardware, all operations are audited, access is controlled by IAM policy. However, calling KMS for every HTTP signature introduces latency (5-50ms per call) and cost that is prohibitive at high request rates.

### The Envelope Pattern

The solution is to use KMS to protect a wrapping key or to generate ephemeral signing key pairs, then sign locally at full speed.

**Flow:**

1. **At boot or rotation interval:** Call KMS to obtain a signing key pair.
   - **AWS:** `GenerateDataKeyPair` with `KeyPairSpec=ECC_NIST_P256` returns the private key in plaintext and encrypted.
   - **GCP:** Unwrap a stored encrypted private key using Cloud KMS decrypt.
   - **Azure:** Similar unwrap pattern with Key Vault.

2. **Cache in process memory:** The plaintext private key lives only in memory, never on disk. Tag it with a key identifier (e.g., a timestamp or rotation counter).

3. **Sign locally:** ECDSA P-256 signing is ~10,000-50,000 operations/sec on a single core. This is never the bottleneck.

4. **Publish the public key:** Make the corresponding public key available to verifiers via a JWKS endpoint, `.well-known` resource, or `keyid` resolution mechanism.

5. **Rotate on a schedule:** Generate a new key pair periodically (e.g., hourly). Start signing with the new key, but keep the old public key published for a grace period to cover in-flight requests.

### Key Identification and Rotation

The `keyid` parameter in the signature metadata tells verifiers which key to use:

```
Signature-Input: sig1=("@method" "@target-uri" "content-digest")
    ;keyid="2025-02-26T18:00Z";alg="ecdsa-p256-sha256"
    ;created=1740592800
```

The verifier resolves `keyid="2025-02-26T18:00Z"` to a public key. During rotation windows, multiple keys are valid simultaneously. The JWKS endpoint should list both the current and previous key, removing the old one after the grace period.

### Multi-Instance Deployments

If multiple service instances need to produce signatures that any verifier can check:

**Option A: Shared wrapped key.** Store the KMS-encrypted private key in a secrets store (e.g., AWS Secrets Manager, HashiCorp Vault). Each instance calls KMS to unwrap it at boot. All instances sign with the same key, so verifiers need only one public key per rotation window.

**Option B: Per-instance keys.** Each instance generates its own key pair via KMS. All public keys are published. Verifiers resolve `keyid` to the appropriate public key. This is more complex but avoids sharing private key material across instances.

**Recommendation:** Option A (shared wrapped key) is simpler and sufficient for most deployments. Use Option B only if your threat model specifically requires that a compromised instance cannot produce signatures attributable to other instances.

### Audit Trail

The security story for auditors: "Private signing keys are generated and encrypted by KMS. The encrypted key is stored in [secrets store]. At runtime, each instance calls KMS to decrypt the key into process memory. KMS logs every decrypt operation in CloudTrail/Cloud Audit Logs. Keys are rotated every [interval]. The plaintext key never touches disk."

This satisfies most compliance frameworks (SOC 2, PCI-DSS, etc.) while allowing local signing at any throughput.

### Algorithm Choice

For HTTP message signatures with the envelope pattern:

| Algorithm | Speed (ops/sec/core) | KMS Support | Notes |
|---|---|---|---|
| ECDSA P-256 | ~10,000-50,000 | AWS, GCP, Azure | Best balance of speed, security, and compatibility |
| ECDSA P-384 | ~5,000-20,000 | AWS, GCP, Azure | Higher security margin, lower throughput |
| Ed25519 | ~50,000-100,000 | GCP only (as of early 2025) | Fastest, but limited KMS support |
| RSA 2048 | ~1,000-5,000 | AWS, GCP, Azure | Slower, larger signatures |

**Recommendation:** ECDSA P-256 (`ecdsa-p256-sha256` in RFC 9421) unless you have a specific reason to choose otherwise. It has universal KMS support, compact signatures, and sufficient throughput for any practical HTTP signing workload.

See [Algorithms](/concepts/algorithms) for algorithm details and [Key Management](/concepts/key-management) for the key interfaces and platform-specific integration (HSM, Secure Enclave, Android Keystore, Web Crypto).

## Implementation Checklist

For implementors of applications using this library, the following behaviors should be supported or enforced.

### Signing Responses

- Support the `req` parameter on component identifiers to include request components in response signatures.
- Support covering `"signature";req;key="<label>"` to chain to a specific request signature.
- Include `created` and optionally `expires` in signature parameters.
- Use [Content-Digest](/concepts/content-digest) (RFC 9530) for body integrity rather than directly signing body content.

### Verifying Responses (Client Side)

- When a response signature covers a request signature via `"signature";req;key="<label>"`, verify the request signature first against the client's own known key.
- Resolve the server's public key through a trusted channel (`keyid` to JWKS, pre-configured key, etc.).
- Reject signatures with unknown or untrusted `keyid` values.
- Enforce minimum coverage requirements defined by the application profile.
- Check `created` and `expires` to reject stale signatures.

### Intermediary Handling

- When adding a proxy signature, append to the `Signature` and `Signature-Input` dictionaries, never replace existing members.
- Preserve all existing signature dictionary members through the proxy.
- Document any headers that the proxy adds or modifies, so upstream signers can avoid covering those components.

### Key Management

- Support configurable `keyid` values that map to key material.
- Support key rotation with overlapping validity windows.
- Provide hooks for KMS-based key unwrapping at initialization.
- Never persist plaintext private keys to disk.

## References

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) -- HTTP Message Signatures
- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) -- Digest Fields (Content-Digest)
- [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) -- Structured Field Values for HTTP
- [RFC 9421, Section 2.4](https://www.rfc-editor.org/rfc/rfc9421#section-2.4) -- Signing Request Components in a Response Message
- [RFC 9421, Section 7.3.4](https://www.rfc-editor.org/rfc/rfc9421#section-7.3.4) -- Key Specification Mixup
- [RFC 9421, Section 7.3.7](https://www.rfc-editor.org/rfc/rfc9421#section-7.3.7) -- Signing Signature Values
- [RFC 9421, Section 4.3](https://www.rfc-editor.org/rfc/rfc9421#section-4.3) -- Multiple Signatures
