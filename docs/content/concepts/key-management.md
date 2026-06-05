---
sidebar_position: 4
---

# Key Management

httpsig separates key management from the signing/verification logic through the `SigningKey`, `VerifyingKey`, and `KeyProvider` interfaces. This makes it straightforward to plug in different key storage backends.

## Key Interfaces

All languages define the same two core interfaces:

**SigningKey** holds a private key and can produce signatures:

```go
// Go
type SigningKey interface {
    KeyID() string
    Algorithm() Algorithm
    Sign(data []byte) ([]byte, error)
}
```

```typescript
// TypeScript
interface SigningKey {
    keyId: string;
    algorithm: Algorithm;
    sign(data: Uint8Array): Promise<Uint8Array>;
}
```

```java
// Java
public interface SigningKey {
    String keyId();
    Algorithm algorithm();
    byte[] sign(byte[] data) throws HttpSigException;
}
```

**VerifyingKey** holds a public key (or shared secret) and can verify signatures:

```go
// Go
type VerifyingKey interface {
    KeyID() string
    Algorithm() Algorithm
    Verify(data, signature []byte) (bool, error)
}
```

## KeyPair

A `KeyPair` bundles a `SigningKey` and `VerifyingKey` that share the same key ID and algorithm. This is the recommended way to manage keys when you need both sides (e.g., a client that signs requests and verifies responses).

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
// Auto-detect algorithm from key type, derive public key
kp, err := httpsig.NewKeyPair("my-key-id", privateKey)

// HMAC (symmetric)
kp := httpsig.NewHMACKeyPair("my-key-id", secret)
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
// Auto-detect algorithm, derive public key
const kp = newKeyPair('my-key-id', privateKeyObject);

// HMAC (symmetric)
const kp = newHMACKeyPair('my-key-id', secret);
```

</TabItem>
<TabItem value="java" label="Java">

```java
// From java.security.KeyPair (auto-detects algorithm)
var kp = Keys.keyPair("my-key-id", jcaKeyPair);

// HMAC (symmetric)
var kp = Keys.hmacKeyPair("my-key-id", secret);
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
// Static factories per algorithm
let kp = KeyPair.ed25519(keyId: "my-key", privateKey: privKey)
let kp = KeyPair.hmacSHA256(keyId: "my-key", secret: secret)
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
// From java.security.KeyPair (auto-detects algorithm)
val kp = Keys.keyPair("my-key-id", jcaKeyPair)

// HMAC (symmetric)
val kp = Keys.hmacKeyPair("my-key-id", secret)
```

</TabItem>
</Tabs>

## Auto-Detection

Instead of choosing an algorithm-specific constructor, you can pass any standard private or public key and let the library detect the algorithm:

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
signingKey, err := httpsig.NewSigningKeyFromSigner("my-key", signer)
verifyingKey, err := httpsig.NewVerifyingKeyFromPublic("my-key", pubKey)
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
const signingKey = newSigningKey('my-key', privateKeyObject);
const verifyingKey = newVerifyingKey('my-key', publicKeyObject);
```

</TabItem>
<TabItem value="java" label="Java">

```java
var signingKey = Keys.signingKey("my-key", privateKey);
var verifyingKey = Keys.verifyingKey("my-key", publicKey);
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
val signingKey = Keys.signingKey("my-key", privateKey)
val verifyingKey = Keys.verifyingKey("my-key", publicKey)
```

</TabItem>
</Tabs>

Swift uses per-algorithm `KeyPair` factories rather than runtime auto-detection, since CryptoKit types are statically typed.

## In-Memory Keys

The explicit-algorithm approach. Every language provides factory functions for each algorithm:

| Algorithm        | Go                              | TypeScript                     | Java                              | Swift                         | Kotlin                         |
|------------------|---------------------------------|--------------------------------|-----------------------------------|-------------------------------|--------------------------------|
| Ed25519 (sign)   | `NewEd25519SigningKey()`        | `newEd25519SigningKey()`       | `Keys.ed25519SigningKey()`        | `Ed25519SigningKey()`         | `Keys.ed25519SigningKey()`     |
| Ed25519 (verify) | `NewEd25519VerifyingKey()`      | `newEd25519VerifyingKey()`     | `Keys.ed25519VerifyingKey()`      | `Ed25519VerifyingKey()`       | `Keys.ed25519VerifyingKey()`   |
| ECDSA (sign)     | `NewECDSAP256SigningKey()`      | `newECDSAP256SigningKey()`     | `Keys.ecdsaP256SigningKey()`      | `ECDSAP256SigningKey()`       | `Keys.ecdsaP256SigningKey()`   |
| RSA-PSS (sign)   | `NewRSAPSSSigningKey()`         | `newRSAPSSSigningKey()`        | `Keys.rsaPSSSigningKey()`         | `RSAPSSSigningKey()`          | `Keys.rsaPSSSigningKey()`      |
| HMAC (both)      | `NewHMACSHA256Key()`            | `newHMACSHA256Key()`           | `Keys.hmacSHA256Key()`            | `HMACSHA256Key()`             | `Keys.hmacSHA256Key()`         |

HMAC keys implement both `SigningKey` and `VerifyingKey` since the same secret is used for both operations.

## HSM and PKCS#11 (Go)

Go's `crypto.Signer` interface is implemented by most HSM and PKCS#11 libraries. `NewSigningKeyFromSigner` auto-detects the algorithm from the signer's public key:

```go
// Auto-detect algorithm from the signer's public key type
key, err := httpsig.NewSigningKeyFromSigner("hsm-key-id", hsmSigner)

// Or specify the algorithm explicitly
key, err := httpsig.NewSignerKey("hsm-key-id", httpsig.AlgorithmEd25519, hsmSigner)
```

This works with any Go library that provides `crypto.Signer`, including:

- [crypto11](https://github.com/ThalesIgnite/crypto11) (PKCS#11)
- [go-pkcs11](https://github.com/miekg/pkcs11)
- AWS CloudHSM
- Google Cloud KMS

## Apple Secure Enclave (Swift)

On Apple platforms, the Secure Enclave provides hardware-backed P-256 key storage. Use `SecureEnclaveSigningKey` for a streamlined API that automatically derives the verifying key:

```swift
import HTTPSig
import CryptoKit

let seKey = SecureEnclave.P256.Signing.PrivateKey()
let signingKey = SecureEnclaveSigningKey(keyId: "se-key", privateKey: seKey)
// signingKey.verifyingKey is derived automatically
```

For lower-level `SecKey`-based access, you can also use `KeyPair.rsaPSS(keyId:secKey:)` or the explicit constructors directly.

## Android Keystore (Kotlin/Java)

On Android, keys can be stored in the hardware-backed Keystore. Load the `PrivateKey` from the Keystore and wrap it using the `Keys` factory:

```kotlin
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import io.zrz.httpsig.Keys

// Generate a key in the Android Keystore
val keyGen = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
)
keyGen.initialize(
    KeyGenParameterSpec.Builder("my-key-id", KeyProperties.PURPOSE_SIGN)
        .setDigests(KeyProperties.DIGEST_SHA256)
        .build()
)
keyGen.generateKeyPair()

// Load and use
val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
val privateKey = keyStore.getKey("my-key-id", null) as java.security.PrivateKey
val signingKey = Keys.signingKey("my-key-id", privateKey) // auto-detects ECDSA P-256
```

## Web Crypto API (TypeScript)

TypeScript's sign/verify operations are `async` specifically to support the Web Crypto API. Built-in adapters wrap `CryptoKey` instances:

```typescript
import { newWebCryptoSigningKey, newWebCryptoVerifyingKey } from '@zourzouvillys/httpsig';

const signingKey = newWebCryptoSigningKey('my-key', cryptoKey, 'ed25519');
const verifyingKey = newWebCryptoVerifyingKey('my-key', cryptoKey, 'ed25519');
```

The algorithm must be specified explicitly since `CryptoKey` does not expose a standard type field that maps directly to RFC 9421 algorithm identifiers.

## KeyProvider

The `KeyProvider` is used during verification to resolve a `keyId` (from the signature metadata) to a `VerifyingKey`. Implementations can look up keys from a database, JWKS endpoint, file system, or any other source:

```go
// Go: KeyProvider is a function type
provider := func(keyID string, alg httpsig.Algorithm) (httpsig.VerifyingKey, error) {
    key, ok := keyRegistry[keyID]
    if !ok {
        return nil, fmt.Errorf("unknown key: %s", keyID)
    }
    return key, nil
}
```

```java
// Java: KeyProvider is a @FunctionalInterface
KeyProvider provider = (keyId, algorithm) -> keyRegistry.get(keyId);
```

```kotlin
// Kotlin: KeyProvider is a fun interface (SAM)
val provider = KeyProvider { keyId, algorithm -> keyRegistry[keyId] }
```
