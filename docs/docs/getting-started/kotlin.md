---
sidebar_position: 5
---

# Kotlin

## Installation

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("io.zrz:httpsig-kotlin")

    // Optional: OkHttp integration
    implementation("io.zrz:httpsig-kotlin-okhttp")
}
```

Requires Kotlin 2.1.10+, JVM target 17. Uses the same JCA cryptographic providers as Java (RSASSA-PSS, Ed25519, SHA256withECDSAinP1363Format, HmacSHA256).

## Quick Example: Sign a Request

```kotlin
import io.zrz.httpsig.*
import java.time.Instant

// Create a key pair (auto-detects algorithm from JCA key type)
val kp = Keys.keyPair("my-key-id", KeyPairGenerator.getInstance("Ed25519").generateKeyPair())
val key = kp.signingKey

// Build signature parameters
val params = SignatureParameters.builder()
    .component("@method")
    .component("@path")
    .component("@authority")
    .component("content-type")
    .keyId("my-key-id")
    .created(Instant.now())
    .build()

// Sign the message
val result = Signer.sign(httpMessage, "sig1", params, key)

// Apply signature headers
request.addHeader("Signature-Input", Signer.signatureInputHeader(result))
request.addHeader("Signature", Signer.signatureHeader(result))
```

## Quick Example: Verify a Signature

```kotlin
import io.zrz.httpsig.*

// Set up a KeyProvider (auto-detects algorithm from JCA key type)
val provider = KeyProvider { keyId, _ ->
    val pub = keyStore[keyId] ?: return@KeyProvider null
    Keys.verifyingKey(keyId, pub)
}

// Verify
val result = Verifier.verify(
    msg = httpMessage,
    provider = provider,
    options = Verifier.VerifyOptions(
        requiredComponents = listOf(
            ComponentIdentifier.of("@method"),
            ComponentIdentifier.of("@authority"),
        ),
        maxAge = java.time.Duration.ofMinutes(5),
        rejectExpired = true,
    ),
)

println("Verified: label=${result.label}, keyId=${result.keyId}")
```

## HTTP Client Integrations

### OkHttp

```kotlin
import io.zrz.httpsig.okhttp.SigningInterceptor

val interceptor = SigningInterceptor(
    key = signingKey,
    paramsFactory = { request ->
        SignatureParameters.builder()
            .component("@method")
            .component("@authority")
            .keyId("my-key")
            .created(Instant.now())
            .build()
    },
)

val client = OkHttpClient.Builder()
    .addInterceptor(interceptor)
    .build()
```

See the [Integrations Guide](/docs/guides/integrations) for more details.

## Kotlin Idioms

The Kotlin implementation uses language-idiomatic patterns:

- `Algorithm` is a `sealed class` with `data object` members (`Algorithm.Ed25519`, `Algorithm.RsaPssSha512`, etc.)
- `KeyProvider` is a `fun interface` (SAM), so you can pass a lambda directly
- `SignatureParameters` is a `data class` with a builder pattern
- `RawMessage` is a `sealed class` for testing
- Error handling uses `HttpSigException` (checked exceptions are not enforced in Kotlin)
