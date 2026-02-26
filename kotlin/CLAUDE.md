# Kotlin Implementation

## Build and Test

```bash
cd kotlin
./gradlew check                   # all tests (core + integrations)
./gradlew :lib:test               # core tests only
./gradlew :integrations:okhttp:test
./gradlew :integrations:ktor:test
```

## Conventions

- Package: `com.zourzouvillys.httpsig`
- JVM-only (not KMP), Kotlin 2.1.10, JVM target 17
- Gradle multi-module with version catalog at `gradle/libs.versions.toml`
- `Algorithm` is a sealed class with `data object` singletons (not enum)
- `RawMessage` is a sealed class with `Request` / `Response` subclasses
- `KeyProvider` is a `fun interface` (supports SAM lambda conversion)
- `Signer` / `Verifier` / `Keys` / `SFV` are `object` singletons
- `SignatureParameters` uses builder: `.builder().component("x").keyId("y").build()`
- `ComponentIdentifier` is a data class
- `HttpSigException` is the base exception

## JCA Crypto (same as Java)

- RSA-PSS: `Signature.getInstance("RSASSA-PSS")` with SHA-512 / MGF1-SHA512
- ECDSA P-256: `SHA256withECDSAinP1363Format` (raw r||s, 64 bytes)
- Ed25519: `Signature.getInstance("Ed25519")`
- HMAC-SHA256: `Mac.getInstance("HmacSHA256")`

## RSA Key Quirks

- Private key file has RSASSA-PSS OID, public key has plain RSA OID
- Try `KeyFactory.getInstance("RSA")` first, fall back to `"RSASSA-PSS"`

## Integration Modules

| Module | Package | Pattern |
|---|---|---|
| `integrations/okhttp` | `c.z.httpsig.okhttp` | `SigningInterceptor` implements OkHttp `Interceptor` |
| `integrations/ktor` | `c.z.httpsig.ktor` | `HttpSig` plugin via `createClientPlugin` |

- OkHttp 4.12.0, Ktor 3.0.3
- Adapters (`OkHttpMessage`, `KtorMessage`) are `internal`
- Integration modules depend on `:lib` via `api(project(":lib"))`

## Key files

| File | Purpose |
|---|---|
| `Signer.kt` | `sign()`, `signatureInputHeader()`, `signatureHeader()` |
| `Verifier.kt` | `verify()`, `VerifyOptions`, `VerifyResult` |
| `Keys.kt` | Factory object for all key types |
| `Algorithm.kt` | Sealed class with `fromValue()` |
| `SFV.kt` | RFC 8941 parser/serializer |
| `SignatureBase.kt` | Signature base construction |
| `VectorTest.kt` | Shared test vectors with `@TestFactory` |
