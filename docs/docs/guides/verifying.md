---
sidebar_position: 2
---

# Verifying Signatures

This guide covers verifying HTTP Message Signatures in all five languages.

## Step 1: Implement a KeyProvider

The `KeyProvider` resolves a key ID (from the signature metadata) to a `VerifyingKey`. This is where you look up keys from your database, JWKS endpoint, configuration file, or wherever you store them.

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
// Go: KeyProvider is a function type
provider := func(keyID string, alg httpsig.Algorithm) (httpsig.VerifyingKey, error) {
    switch keyID {
    case "client-a":
        return httpsig.NewEd25519VerifyingKey(keyID, clientAPublicKey), nil
    case "client-b":
        return httpsig.NewECDSAP256VerifyingKey(keyID, clientBPublicKey), nil
    default:
        return nil, fmt.Errorf("unknown key: %s", keyID)
    }
}
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import type { KeyProvider } from '@zourzouvillys/httpsig';
import { newEd25519VerifyingKey } from '@zourzouvillys/httpsig';

const provider: KeyProvider = async (keyId, algorithm) => {
  const publicKey = await loadPublicKey(keyId);
  if (!publicKey) throw new Error(`unknown key: ${keyId}`);
  return newEd25519VerifyingKey(keyId, publicKey);
};
```

</TabItem>
<TabItem value="java" label="Java">

```java
// Java: KeyProvider is a @FunctionalInterface
KeyProvider provider = (keyId, algorithm) -> {
    PublicKey pub = keyStore.get(keyId);
    if (pub == null) return null;
    return Keys.ed25519VerifyingKey(keyId, pub);
};
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
// Swift: implement the KeyProvider protocol
struct MyKeyProvider: KeyProvider {
    let keys: [String: Curve25519.Signing.PublicKey]

    func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? {
        guard let pub = keys[keyId] else { return nil }
        return Ed25519VerifyingKey(keyId: keyId, publicKey: pub)
    }
}
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
// Kotlin: KeyProvider is a fun interface (SAM)
val provider = KeyProvider { keyId, algorithm ->
    val pub = keyStore[keyId] ?: return@KeyProvider null
    Keys.ed25519VerifyingKey(keyId, pub)
}
```

</TabItem>
</Tabs>

## Step 2: Configure Verification Options

Verification options let you enforce policies on incoming signatures: which components must be covered, how old signatures can be, and whether expired signatures are rejected.

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
opts := &httpsig.VerifyOptions{
    RequiredComponents: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@authority"),
    },
    MaxAge:        5 * time.Minute,
    RejectExpired: httpsig.BoolPtr(true),
}
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import type { VerifyOptions } from '@zourzouvillys/httpsig';
import { component } from '@zourzouvillys/httpsig';

const opts: VerifyOptions = {
  requiredComponents: [component('@method'), component('@authority')],
  maxAgeMs: 5 * 60 * 1000,
  rejectExpired: true,
};
```

</TabItem>
<TabItem value="java" label="Java">

```java
var opts = new Verifier.VerifyOptions(
    List.of(
        ComponentIdentifier.of("@method"),
        ComponentIdentifier.of("@authority")
    ),
    Duration.ofMinutes(5),
    true,
    null,
    null
);
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
let opts = VerifyOptions(
    requiredComponents: [.init("@method"), .init("@authority")],
    maxAge: 300
)
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
val opts = Verifier.VerifyOptions(
    requiredComponents = listOf(
        ComponentIdentifier.of("@method"),
        ComponentIdentifier.of("@authority"),
    ),
    maxAge = Duration.ofMinutes(5),
    rejectExpired = true,
)
```

</TabItem>
</Tabs>

## Step 3: Verify

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
result, err := httpsig.VerifyMessage(msg, provider, opts, nil)
if err != nil {
    // signature invalid, missing, or expired
    return err
}

fmt.Printf("Verified: label=%s, keyId=%s, algorithm=%s\n",
    result.Label, result.KeyID, result.Algorithm)
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import { verifyMessage } from '@zourzouvillys/httpsig';

try {
  const result = await verifyMessage(msg, provider, opts);
  console.log(`Verified: label=${result.label}, keyId=${result.keyId}`);
} catch (err) {
  // MissingSignatureError, InvalidSignatureError, or MalformedInputError
  console.error('Verification failed:', err);
}
```

</TabItem>
<TabItem value="java" label="Java">

```java
try {
    Verifier.VerifyResult result = Verifier.verify(httpMessage, provider, opts, null);
    System.out.println("Verified: " + result.label() + " by " + result.keyId());
} catch (HttpSigException e) {
    // signature invalid or missing
}
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
do {
    let result = try Verifier.verify(msg: httpMessage, provider: keyProvider, options: opts)
    print("Verified: label=\(result.label), keyId=\(result.keyId)")
} catch {
    // HttpSigError: missingSignature, invalidSignature, signatureExpired, etc.
    print("Verification failed: \(error)")
}
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
try {
    val result = Verifier.verify(httpMessage, provider, opts)
    println("Verified: label=${result.label}, keyId=${result.keyId}")
} catch (e: HttpSigException) {
    println("Verification failed: ${e.message}")
}
```

</TabItem>
</Tabs>

## Verification Process

Under the hood, `verifyMessage` performs these steps:

1. Parse the `Signature-Input` header as an SFV dictionary to get the list of signatures.
2. Parse the `Signature` header to get the raw signature bytes for each label.
3. For each signature (or just the one matching `requiredLabel`):
   a. Extract the covered components and metadata from the inner list.
   b. Check that all `requiredComponents` are covered.
   c. Check time constraints (`maxAge`, `rejectExpired`).
   d. Resolve the key via the `KeyProvider`.
   e. Reconstruct the signature base from the message.
   f. Verify the cryptographic signature.
4. Return the first signature that passes all checks, or an error if none do.

## Error Handling

All implementations distinguish between these error cases:

- **Missing signature**: no `Signature-Input` or `Signature` headers found
- **Malformed input**: headers present but cannot be parsed as SFV
- **Invalid signature**: signature present but cryptographic verification failed
- **Expired**: signature is older than `maxAge` or past its `expires` time
- **Key not found**: the `KeyProvider` returned no key for the given `keyId`

## Verifying Response Signatures

To verify a response signature that includes request-bound components (`;req`), pass the original request as the `reqMsg` parameter:

```go
result, err := httpsig.VerifyMessage(responseMsg, provider, opts, requestMsg)
```

This allows the verifier to extract `@method;req`, `@authority;req`, and other request components from the original request when reconstructing the signature base.
