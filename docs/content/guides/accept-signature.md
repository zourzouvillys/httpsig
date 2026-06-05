---
sidebar_position: 6
---

# Signature Negotiation

RFC 9421 Section 5 defines the `Accept-Signature` header, which allows either party to request that the other sign messages with specific components, algorithms, and keys. httpsig provides `SignatureRequirements` as a shared type that drives both verification filtering and Accept-Signature header generation, keeping them in sync.

## SignatureRequirements

`SignatureRequirements` captures what a valid signature must look like:

- **components** -- which HTTP components must be signed
- **keyId** -- which key the signer should use
- **algorithm** -- which algorithm to use
- **tag** -- application-specific tag for multi-signature scenarios
- **requireCreated / requireExpires** -- whether timestamps must be present

This same type is used in three ways:

1. **Verification filtering** -- pass it as `VerifyOptions.requirements` to filter signatures by components, keyId, algorithm, and tag
2. **Accept-Signature building** -- serialize it to an `Accept-Signature` header value
3. **Signing** -- convert it to `SignatureParameters` when a client needs to sign a request matching what the server asked for

## Server: Requesting a Signature

When a server receives an unsigned request (or one without a matching signature), it can respond with `Accept-Signature` to tell the client what to sign.

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
// Define what you require — same config for both verification and negotiation
reqs := &httpsig.SignatureRequirements{
    Components: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@authority"),
        httpsig.Component("content-digest"),
    },
    KeyID:          "client-key-1",
    Algorithm:      httpsig.AlgorithmECDSAP256SHA256,
    RequireCreated: true,
}

// Try to verify
result, err := httpsig.VerifyMessage(msg, provider, &httpsig.VerifyOptions{
    Requirements: reqs,
}, nil)

if err != nil {
    // No valid signature — tell the client what we want
    header := httpsig.BuildAcceptSignature(map[string]httpsig.SignatureRequirements{
        "sig1": *reqs,
    })
    w.Header().Set("Accept-Signature", header)
    w.WriteHeader(http.StatusUnauthorized)
    return
}
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import {
  verifyMessage, buildAcceptSignature,
  component, type SignatureRequirements,
} from '@zourzouvillys/httpsig';

const reqs: SignatureRequirements = {
  components: [component('@method'), component('@authority'), component('content-digest')],
  keyId: 'client-key-1',
  algorithm: 'ecdsa-p256-sha256',
  requireCreated: true,
};

try {
  const result = await verifyMessage(msg, provider, { requirements: reqs });
} catch {
  const header = buildAcceptSignature({ sig1: reqs });
  res.setHeader('Accept-Signature', header);
  res.status(401).end();
}
```

</TabItem>
<TabItem value="java" label="Java">

```java
var reqs = AcceptSignature.SignatureRequirements.builder()
    .component("@method")
    .component("@authority")
    .component("content-digest")
    .keyId("client-key-1")
    .algorithm(Algorithm.ECDSA_P256_SHA256)
    .requireCreated(true)
    .build();

try {
    var result = Verifier.verify(httpMessage, provider,
        Verifier.VerifyOptions.builder().requirements(reqs).build(), null);
} catch (HttpSigException e) {
    String header = AcceptSignature.build(Map.of("sig1", reqs));
    response.setHeader("Accept-Signature", header);
    response.setStatus(401);
}
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
let reqs = SignatureRequirements(
    components: [.init("@method"), .init("@authority"), .init("content-digest")],
    keyId: "client-key-1",
    algorithm: .ecdsaP256Sha256,
    requireCreated: true
)

do {
    let result = try Verifier.verify(
        msg: httpMessage,
        provider: keyProvider,
        options: VerifyOptions(requirements: reqs)
    )
} catch {
    let header = AcceptSignature.build(["sig1": reqs])
    response.setValue(header, forHTTPHeaderField: "Accept-Signature")
    response.statusCode = 401
}
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
val reqs = SignatureRequirements(
    components = listOf(
        ComponentIdentifier.of("@method"),
        ComponentIdentifier.of("@authority"),
        ComponentIdentifier.of("content-digest"),
    ),
    keyId = "client-key-1",
    algorithm = Algorithm.EcdsaP256Sha256,
    requireCreated = true,
)

try {
    val result = Verifier.verify(httpMessage, provider,
        Verifier.VerifyOptions(requirements = reqs))
} catch (e: HttpSigException) {
    val header = AcceptSignature.build(mapOf("sig1" to reqs))
    response.setHeader("Accept-Signature", header)
    response.status = 401
}
```

</TabItem>
</Tabs>

## Client: Processing Accept-Signature

When a client receives a response with an `Accept-Signature` header (typically on a 401), it can parse it, convert to signing parameters, and retry with the requested signature.

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
// Parse the server's requirements
reqs, err := httpsig.ParseAcceptSignature(resp.Header.Get("Accept-Signature"))
if err != nil {
    return err
}

// Convert to signing parameters
if entry, ok := reqs["sig1"]; ok {
    params := entry.ToSignatureParameters(
        httpsig.Int64Ptr(time.Now().Unix()),  // created
        nil,                                   // expires
        nil,                                   // nonce
    )
    result, err := httpsig.SignMessage(msg, "sig1", params, signingKey, nil)
    // ... add result headers and retry
}
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import { parseAcceptSignature, toSignatureParameters, signMessage } from '@zourzouvillys/httpsig';

const reqs = parseAcceptSignature(response.headers.get('Accept-Signature')!);
const entry = reqs['sig1'];

if (entry) {
  const params = toSignatureParameters(entry, {
    created: Math.floor(Date.now() / 1000),
  });
  const result = await signMessage(msg, 'sig1', params, signingKey);
  // ... add result headers and retry
}
```

</TabItem>
<TabItem value="java" label="Java">

```java
var reqs = AcceptSignature.parse(response.header("Accept-Signature"));
var entry = reqs.get("sig1");

if (entry != null) {
    var params = entry.toSignatureParameters(
        Instant.now().getEpochSecond(), null, null);
    var result = Signer.sign(httpMessage, "sig1", params, signingKey, null);
    // ... add result headers and retry
}
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
let reqs = try AcceptSignature.parse(response.value(forHTTPHeaderField: "Accept-Signature")!)

if let entry = reqs["sig1"] {
    let params = entry.signatureParameters(
        created: Int64(Date().timeIntervalSince1970),
        expires: nil,
        nonce: nil
    )
    let result = try Signer.sign(msg: httpMessage, label: "sig1", params: params, key: signingKey)
    // ... add result headers and retry
}
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
val reqs = AcceptSignature.parse(response.header("Accept-Signature")!!)
val entry = reqs["sig1"]

if (entry != null) {
    val params = entry.toSignatureParameters(
        created = Instant.now().epochSecond, expires = null, nonce = null)
    val result = Signer.sign(httpMessage, "sig1", params, signingKey)
    // ... add result headers and retry
}
```

</TabItem>
</Tabs>

## Accept-Signature Header Format

The `Accept-Signature` header is an [SFV Dictionary](https://www.rfc-editor.org/rfc/rfc8941#section-3.2) where each member key is a signature label and the value is an inner list of required components with constraint parameters:

```
Accept-Signature: sig1=("@method" "@authority" "content-digest");keyid="client-key-1";alg="ecdsa-p256-sha256";created;tag="myapp"
```

Parameters:

| Parameter | Type | Meaning |
|---|---|---|
| `keyid` | string | Which key the signer should use |
| `alg` | string | Which algorithm to use |
| `nonce` | string | Nonce the signer must include |
| `tag` | string | Application-specific tag |
| `created` | boolean | Signer must include a `created` timestamp |
| `expires` | boolean | Signer must include an `expires` timestamp |

Note that `created` and `expires` are bare booleans here (requesting their **presence**), unlike in `Signature-Input` where they carry epoch timestamps.

## Using Requirements for Verification

`SignatureRequirements` can be passed to `VerifyOptions.requirements` to filter signatures during verification. When set, the verifier checks:

1. All required **components** are covered by the signature
2. The signature's **keyId** matches (if specified in requirements)
3. The signature's **algorithm** matches (if specified)
4. The signature's **tag** matches (if specified)

This is a superset of the existing `requiredComponents` option. Both continue to work -- `requirements` takes precedence when set, and `requiredComponents` is used as a fallback for backward compatibility.
