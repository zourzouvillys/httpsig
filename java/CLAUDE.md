# Java Implementation

## Build and Test

```bash
cd java
./gradlew check         # all tests (core + integrations)
./gradlew :lib:test     # core tests only
```

## Conventions

- Package: `com.zourzouvillys.httpsig`
- Java 17+, Gradle multi-module
- `SignatureParameters` uses builder pattern: `.builder().component("@method").keyId("x").created(Instant.now()).build()`
- `ComponentIdentifier` is a Java record with `Map<String, Object>` params
- `KeyProvider` is a functional interface: `(keyId, algorithm) -> VerifyingKey`
- `Keys` is a factory class with static methods for all key types
- `RawMessage` is a concrete `HttpMessage` for testing
- Algorithm param in `SignatureParameters` is optional; test vectors omit `alg=`
- `VerifyOptions` record: `(requiredComponents, maxAge, maxClockSkew, rejectExpired, requiredLabel, now)`
- `maxClockSkew` rejects future-dated `created` timestamps
- Verifier checks `alg` parameter against resolved key's algorithm
- Integration modules use `api(project(":lib"))` for transitive dependency

## RSA Key Quirks

- Private key file has RSASSA-PSS OID, public key has plain RSA OID
- In test code: try `KeyFactory.getInstance("RSA")` first, fall back to `"RSASSA-PSS"`
- EC P-256 test keys are SEC1 format, need ASN.1 PKCS#8 wrapping

## Integration Modules

| Module | Package | Pattern |
|---|---|---|
| `integrations/okhttp` | `c.z.httpsig.okhttp` | `SigningInterceptor` implements `Interceptor` |
| `integrations/jdk-http` | `c.z.httpsig.jdkhttp` | `HttpSigning.sign(HttpRequest.Builder, ...)` static method |
| `integrations/spring-webclient` | `c.z.httpsig.spring` | `SigningFilterFunction` implements `ExchangeFilterFunction` |

## Key files

| File | Purpose |
|---|---|
| `Signer.java` | `sign()`, `signatureInputHeader()`, `signatureHeader()` |
| `Verifier.java` | `verify()`, `VerifyOptions` |
| `Keys.java` | Factory methods for all key types |
| `SignatureParameters.java` | Builder pattern for signing params |
| `SignatureBase.java` | Signature base construction |
| `SFV.java` | RFC 8941 Structured Field Values parser |
| `VectorTest.java` | Shared test vectors with `@TestFactory` |
