# httpsig - Kotlin

Kotlin JVM implementation of [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) with [Content-Digest (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530) support.

## Install

### Gradle

```kotlin
implementation("io.zrz:httpsig-kotlin:0.1.0")

// Optional integrations
implementation("io.zrz:httpsig-kotlin-okhttp:0.1.0")
implementation("io.zrz:httpsig-kotlin-ktor:0.1.0")
```

Requires JVM 17+. Kotlin 2.1+.

## Usage

### Signing

```kotlin
import io.zrz.httpsig.*

val key = Keys.ed25519Signing("my-key-id", privateKey)

val params = SignatureParameters.builder()
    .component("@method")
    .component("@authority")
    .component("content-type")
    .keyId("my-key-id")
    .created(Instant.now())
    .build()

val result = Signer.sign(message, "sig1", params, key)

// Add headers
headers["Signature-Input"] = Signer.signatureInputHeader(result)
headers["Signature"] = Signer.signatureHeader(result)
```

### Verification

```kotlin
import io.zrz.httpsig.*

// KeyProvider is a fun interface, supports lambda
val provider = KeyProvider { keyId, _ ->
    Keys.ed25519Verifying(keyId, publicKey)
}

val result = Verifier.verify(message, provider, VerifyOptions(
    maxAge = Duration.ofMinutes(5),
    requiredComponents = listOf(ComponentIdentifier.of("@method")),
))
```

### Integrations

#### OkHttp

```kotlin
import io.zrz.httpsig.okhttp.SigningInterceptor

val interceptor = SigningInterceptor(
    key = signingKey,
    label = "sig1",
) { request ->
    SignatureParameters.builder()
        .component("@method")
        .component("@authority")
        .keyId("my-key")
        .created(Instant.now())
        .build()
}

val client = OkHttpClient.Builder()
    .addInterceptor(interceptor)
    .build()
```

#### Ktor

```kotlin
import io.zrz.httpsig.ktor.HttpSig

val client = HttpClient(CIO) {
    install(HttpSig) {
        key = signingKey
        label = "sig1"
        paramsFactory = { request ->
            SignatureParameters.builder()
                .component("@method")
                .component("@authority")
                .keyId("my-key")
                .created(Instant.now())
                .build()
        }
    }
}
```

## Key Management

### Auto-Detection (Recommended)

```kotlin
// Auto-detect algorithm from JCA key type
val signing = Keys.signingKey("my-key-id", privateKey)
val verifying = Keys.verifyingKey("my-key-id", publicKey)

// KeyPair from java.security.KeyPair (auto-detects)
val kp = Keys.keyPair("my-key-id", jcaKeyPair)

// KeyPair from explicit keys
val kp = Keys.keyPair("my-key-id", privateKey, publicKey)

// HMAC KeyPair
val kp = Keys.hmacKeyPair("my-key-id", secret)
```

The `KeyPair` data class bundles a `SigningKey` and `VerifyingKey` with computed `keyId` and `algorithm` properties.

### Explicit Algorithm Constructors

| Algorithm | Sealed class | Signing Key | Verifying Key |
|---|---|---|---|
| RSA-PSS-SHA512 | `Algorithm.RsaPssSha512` | `Keys.rsaPssSigning(keyId, PrivateKey)` | `Keys.rsaPssVerifying(keyId, PublicKey)` |
| ECDSA P-256 | `Algorithm.EcdsaP256Sha256` | `Keys.ecdsaP256Signing(keyId, PrivateKey)` | `Keys.ecdsaP256Verifying(keyId, PublicKey)` |
| Ed25519 | `Algorithm.Ed25519` | `Keys.ed25519Signing(keyId, PrivateKey)` | `Keys.ed25519Verifying(keyId, PublicKey)` |
| HMAC-SHA256 | `Algorithm.HmacSha256` | `Keys.hmacSha256(keyId, secret)` | Same instance (symmetric) |

All asymmetric keys use `java.security.PrivateKey` / `java.security.PublicKey`.

## Kotlin Idioms

- `Algorithm` is a sealed class with `data object` singletons (exhaustive `when`)
- `RawMessage` is a sealed class with `Request` / `Response` subclasses
- `KeyProvider` is a `fun interface` (SAM conversion, use as lambda)
- `SignatureParameters` uses builder pattern: `.builder().component().keyId().build()`
- `ComponentIdentifier` is a data class with `of()`, `queryParam()`, `req()` factory methods
- `HttpSigException` is the base exception type

## Development

```bash
# Run all tests (core + integrations)
cd kotlin
./gradlew check

# Run only core tests
./gradlew :lib:test

# Run integration tests
./gradlew :integrations:okhttp:test
./gradlew :integrations:ktor:test
```

### Project structure

```
kotlin/
  build.gradle.kts               Root build config
  settings.gradle.kts             Module includes
  gradle/libs.versions.toml       Version catalog
  lib/                            Core library
    src/main/kotlin/.../
      Algorithm.kt                Sealed class with data objects
      Algorithms.kt               Low-level JCA crypto operations
      ComponentIdentifier.kt      Data class with params
      Components.kt               Component extraction
      ContentDigest.kt            RFC 9530
      Errors.kt                   HttpSigException
      HttpMessage.kt              HttpMessage interface
      KeyProvider.kt              fun interface
      Keys.kt                     Key factory object
      RawMessage.kt               Sealed class (Request/Response)
      SFV.kt                      Structured Field Values parser
      SignatureBase.kt            Signature base construction
      SignatureParameters.kt      Builder-pattern params
      Signer.kt                   Object: sign + header formatters
      SigningKey.kt               Interface
      Verifier.kt                 Object: verify + options
      VerifyingKey.kt             Interface
    src/test/kotlin/.../
      SmokeTest.kt                Unit tests
      VectorTest.kt               Shared RFC 9421 test vectors
  integrations/
    okhttp/                       SigningInterceptor
    ktor/                         HttpSig client plugin
```

### Test vectors

Tests load shared vectors from `../../testdata/vectors/*.json`.

## License

Apache License 2.0.
