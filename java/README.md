# httpsig - Java

Java implementation of [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) with [Content-Digest (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530) support.

## Install

### Gradle

```kotlin
implementation("io.zrz:httpsig:0.1.0")

// Optional integrations
implementation("io.zrz:httpsig-okhttp:0.1.0")
implementation("io.zrz:httpsig-jdk-http:0.1.0")
implementation("io.zrz:httpsig-spring-webclient:0.1.0")
```

### Maven

```xml
<dependency>
  <groupId>io.zrz</groupId>
  <artifactId>httpsig</artifactId>
  <version>0.1.0</version>
</dependency>
```

Requires Java 17+.

## Usage

### Signing

```java
import io.zrz.httpsig.*;

var key = Keys.ed25519Signing("my-key-id", privateKey);

var params = SignatureParameters.builder()
    .component("@method")
    .component("@authority")
    .component("content-type")
    .keyId("my-key-id")
    .created(Instant.now())
    .build();

var result = Signer.sign(message, "sig1", params, key, null);

// Add headers
request.setHeader("Signature-Input", Signer.signatureInputHeader(result));
request.setHeader("Signature", Signer.signatureHeader(result));
```

### Verification

```java
KeyProvider provider = (keyId, algorithm) -> Keys.ed25519Verifying(keyId, publicKey);

var result = Verifier.verify(message, provider, Verifier.VerifyOptions.defaults(), null);
```

### Integrations

#### OkHttp

```java
var interceptor = new SigningInterceptor(signingKey, req ->
    SignatureParameters.builder()
        .component("@method")
        .component("@authority")
        .keyId("my-key")
        .created(Instant.now())
        .build()
);

var client = new OkHttpClient.Builder()
    .addInterceptor(interceptor)
    .build();
```

#### JDK HttpClient

```java
var builder = HttpRequest.newBuilder()
    .uri(URI.create("https://example.com/api"))
    .POST(HttpRequest.BodyPublishers.ofString("{}"));

HttpSigning.sign(builder, params, signingKey);
var request = builder.build();
```

#### Spring WebClient

```java
var webClient = WebClient.builder()
    .filter(new SigningFilterFunction(signingKey, req ->
        SignatureParameters.builder()
            .component("@method")
            .component("@authority")
            .keyId("my-key")
            .created(Instant.now())
            .build()
    ))
    .build();
```

## Key Management

### Auto-Detection (Recommended)

```java
// Auto-detect algorithm from JCA key type
var signing = Keys.signingKey("my-key-id", privateKey);
var verifying = Keys.verifyingKey("my-key-id", publicKey);

// KeyPair from java.security.KeyPair (auto-detects)
var kp = Keys.keyPair("my-key-id", jcaKeyPair);

// KeyPair from explicit keys
var kp = Keys.keyPair("my-key-id", privateKey, publicKey);

// HMAC KeyPair
var kp = Keys.hmacKeyPair("my-key-id", secret);
```

The `KeyPair` record bundles a `SigningKey` and `VerifyingKey` with `keyId()` and `algorithm()` accessors.

### Explicit Algorithm Constructors

| Algorithm | Signing Key | Verifying Key |
|---|---|---|
| RSA-PSS-SHA512 | `Keys.rsaPssSigning(keyId, PrivateKey)` | `Keys.rsaPssVerifying(keyId, PublicKey)` |
| ECDSA P-256 | `Keys.ecdsaP256Signing(keyId, PrivateKey)` | `Keys.ecdsaP256Verifying(keyId, PublicKey)` |
| Ed25519 | `Keys.ed25519Signing(keyId, PrivateKey)` | `Keys.ed25519Verifying(keyId, PublicKey)` |
| HMAC-SHA256 | `Keys.hmacSha256(keyId, secret)` | Same instance (symmetric) |

All asymmetric keys use `java.security.PrivateKey` / `java.security.PublicKey`. Load from PEM with `Keys.loadPrivateKey()` / `Keys.loadPublicKey()`.

## Development

```bash
# Run all tests
cd java
./gradlew check

# Run only core tests
./gradlew :lib:test

# Run integration tests
./gradlew :integrations:okhttp:test
./gradlew :integrations:jdk-http:test
./gradlew :integrations:spring-webclient:test
```

### Project structure

```
java/
  build.gradle.kts              Root build config
  settings.gradle.kts           Module includes
  gradle/libs.versions.toml     Version catalog
  lib/                          Core library
    src/main/java/.../
      Algorithm.java            Algorithm enum
      Algorithms.java           Low-level JCA crypto operations
      ComponentIdentifier.java  Component with params (record)
      Components.java           Component extraction
      ContentDigest.java        RFC 9530 Content-Digest
      HttpMessage.java          Message interface
      HttpSigException.java     Exception type
      KeyProvider.java          Key resolution interface
      Keys.java                 Key factory methods
      RawMessage.java           Test/utility message implementation
      SFV.java                  Structured Field Values parser
      SignatureBase.java        Signature base construction
      SignatureParameters.java  Builder-pattern params
      Signer.java               SignMessage + header formatters
      SigningKey.java           Signing key interface
      Verifier.java             VerifyMessage + VerifyOptions
      VerifyingKey.java         Verifying key interface
    src/test/java/.../
      SmokeTest.java            Unit tests
      VectorTest.java           Shared RFC 9421 test vectors
  integrations/
    okhttp/                     OkHttp Interceptor
    jdk-http/                   JDK HttpClient wrapper
    spring-webclient/           Spring WebClient filter
```

### Test vectors

Tests load shared vectors from `../../testdata/vectors/*.json`.

### Notes

- Java algorithm param in `SignatureParameters` is optional. The test vectors don't include `alg=` in params.
- RSA key loading: private key may have RSASSA-PSS OID while public key has plain RSA OID. The test code tries "RSA" KeyFactory first, falls back to "RSASSA-PSS".
- EC P-256 test keys are SEC1 format, need wrapping to PKCS#8 for `KeyFactory`.

## License

Apache License 2.0.
