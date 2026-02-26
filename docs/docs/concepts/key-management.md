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

## In-Memory Keys

The simplest approach. Every language provides factory functions for each algorithm:

| Algorithm        | Go                              | TypeScript                     | Java                              | Swift                         | Kotlin                         |
|------------------|---------------------------------|--------------------------------|-----------------------------------|-------------------------------|--------------------------------|
| Ed25519 (sign)   | `NewEd25519SigningKey()`        | `newEd25519SigningKey()`       | `Keys.ed25519SigningKey()`        | `Ed25519SigningKey()`         | `Keys.ed25519SigningKey()`     |
| Ed25519 (verify) | `NewEd25519VerifyingKey()`      | `newEd25519VerifyingKey()`     | `Keys.ed25519VerifyingKey()`      | `Ed25519VerifyingKey()`       | `Keys.ed25519VerifyingKey()`   |
| ECDSA (sign)     | `NewECDSAP256SigningKey()`      | `newECDSAP256SigningKey()`     | `Keys.ecdsaP256SigningKey()`      | `ECDSAP256SigningKey()`       | `Keys.ecdsaP256SigningKey()`   |
| RSA-PSS (sign)   | `NewRSAPSSSigningKey()`         | `newRSAPSSSigningKey()`        | `Keys.rsaPSSSigningKey()`         | `RSAPSSSigningKey()`          | `Keys.rsaPSSSigningKey()`      |
| HMAC (both)      | `NewHMACSHA256Key()`            | `newHMACSHA256Key()`           | `Keys.hmacSHA256Key()`            | `HMACSHA256Key()`             | `Keys.hmacSHA256Key()`         |

HMAC keys implement both `SigningKey` and `VerifyingKey` since the same secret is used for both operations.

## HSM and PKCS#11 (Go)

Go's `crypto.Signer` interface is implemented by most HSM and PKCS#11 libraries. The `NewSignerKey` function wraps any `crypto.Signer` as a `SigningKey`:

```go
import (
    "crypto"
    "github.com/zourzouvillys/httpsig/golang"
)

// hsmSigner implements crypto.Signer, backed by your HSM
var hsmSigner crypto.Signer = getHSMSigner()

key, err := httpsig.NewSignerKey("hsm-key-id", httpsig.AlgorithmEd25519, hsmSigner)
```

This works with any Go library that provides `crypto.Signer`, including:

- [crypto11](https://github.com/ThalesIgnite/crypto11) (PKCS#11)
- [go-pkcs11](https://github.com/miekg/pkcs11)
- AWS CloudHSM
- Google Cloud KMS

## Apple Secure Enclave (Swift)

On Apple platforms, the Secure Enclave provides hardware-backed key storage for P-256 keys. You can use `SecKey` directly with `ECDSAP256SigningKey` or `RSAPSSSigningKey`:

```swift
import HTTPSig
import Security

// Create or load a Secure Enclave key
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .privateKeyUsage,
    nil
)!

let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
        kSecAttrAccessControl as String: access,
    ],
]

var error: Unmanaged<CFError>?
let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)!

// The key never leaves the Secure Enclave
let signingKey = RSAPSSSigningKey(keyId: "se-key", secKey: privateKey)
```

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
val signingKey = Keys.ecdsaP256SigningKey("my-key-id", privateKey)
```

## Web Crypto API (TypeScript)

TypeScript's sign/verify operations are `async` specifically to support the Web Crypto API. You can implement the `SigningKey` interface using `crypto.subtle`:

```typescript
import type { SigningKey, Algorithm } from '@zourzouvillys/httpsig';

class WebCryptoSigningKey implements SigningKey {
  constructor(
    public readonly keyId: string,
    public readonly algorithm: Algorithm,
    private readonly cryptoKey: CryptoKey,
  ) {}

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign('Ed25519', this.cryptoKey, data);
    return new Uint8Array(sig);
  }
}
```

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
