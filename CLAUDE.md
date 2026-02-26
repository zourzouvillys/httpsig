# httpsig

Multi-language HTTP Message Signatures library implementing RFC 9421.

## Project Structure

Monorepo with five language implementations sharing test vectors:

- `golang/` - Go implementation (package `httpsig`)
- `typescript/` - TypeScript (`@zourzouvillys/httpsig`)
- `java/` - Java (Gradle multi-module, `com.zourzouvillys.httpsig`)
- `swift/` - Swift (SPM, `HTTPSig`)
- `kotlin/` - Kotlin JVM (Gradle multi-module, `com.zourzouvillys.httpsig`)
- `testdata/` - Shared RFC 9421 test vectors (all languages load these)
- `docs/` - Docusaurus documentation site

## Build Commands

```bash
make test-go          # Go tests with race detector
make test-ts          # TypeScript tests (vitest)
make test-java        # Java tests (Gradle)
make test-swift       # Swift tests (SPM)
make test-kotlin      # Kotlin tests (Gradle)
make test-all         # All languages
make lint-go          # go vet + staticcheck
```

## Architecture

Each language implements the same core abstractions:

- **Algorithm**: rsa-pss-sha512, ecdsa-p256-sha256, ed25519, hmac-sha256
- **ComponentIdentifier**: Header name or derived component (@method, @path, etc.)
- **SignatureParameters**: Components list + algorithm + keyId + created/expires/nonce/tag
- **SigningKey / VerifyingKey**: Interfaces wrapping crypto keys (supports HSM, Secure Enclave, etc.)
- **KeyProvider**: Resolves keyId to VerifyingKey
- **signMessage / verifyMessage**: Top-level sign and verify operations

## Testing

- All implementations must pass the shared test vectors in `testdata/vectors/`.
- No mocks. Unit tests and integration tests only.
- Test vectors are derived from RFC 9421 Appendix B.
- Go tests: `*_test.go` files in `golang/`.
- TypeScript tests: `test/*.test.ts` files in `typescript/`, run with vitest.
- Java tests: `src/test/java/` in `java/lib/`, run with `./gradlew test` from `java/`.

## Conventions

- Go package name: `httpsig` (not `golang`)
- Go module path: `github.com/zourzouvillys/httpsig/golang`
- Go middleware: `Transport` (signing RoundTripper), `VerifyMiddleware` / `RequireSignature` (verifying Handler)
- TypeScript package: `@zourzouvillys/httpsig`, ESM-only, Node 20+
- TypeScript sign/verify APIs are async (to support Web Crypto in the future)
- Java package: `com.zourzouvillys.httpsig`, Java 17+, Gradle multi-module
- Java API: `Signer.sign()`, `Verifier.verify()`, `Keys.*` factory methods, `RawMessage` for testing
- Java uses `SignatureParameters.builder()` pattern with `component()`, `keyId()`, `createdEpoch()`, etc.
- Java algorithm param in SignatureParameters is optional; test vectors don't include `alg=` in params
- Error types: use language-idiomatic error handling (Go errors, TS exceptions, Java exceptions, etc.)
- Keep implementations independent. No shared code generation or cross-language tooling.
