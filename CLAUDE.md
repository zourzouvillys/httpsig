# httpsig

Multi-language HTTP Message Signatures library implementing RFC 9421.

Each language has its own `CLAUDE.md` with language-specific conventions. See:
- [`golang/CLAUDE.md`](golang/CLAUDE.md)
- [`typescript/CLAUDE.md`](typescript/CLAUDE.md)
- [`java/CLAUDE.md`](java/CLAUDE.md)
- [`swift/CLAUDE.md`](swift/CLAUDE.md)
- [`kotlin/CLAUDE.md`](kotlin/CLAUDE.md)

## Project Structure

Monorepo with five language implementations sharing test vectors:

```
httpsig/
  golang/          Go (package httpsig, Go 1.22+)
  typescript/      TypeScript (@zourzouvillys/httpsig, Node 20+, ESM)
  java/            Java (io.zrz.httpsig, Java 17+, Gradle)
  swift/           Swift (HTTPSig, macOS 13+/iOS 16+, SPM, Swift 6.0)
  kotlin/          Kotlin JVM (io.zrz.httpsig, JVM 17+, Gradle)
  testdata/        Shared RFC 9421 test vectors (all languages load these)
  docs/            Docusaurus documentation site
  .github/         CI workflows + GitHub templates
```

## Build Commands

```bash
# Individual languages
cd golang && go test -race ./...
cd typescript && npm ci && npm test
cd java && ./gradlew check
cd swift && swift test
cd kotlin && ./gradlew check

# Docs
cd docs && npm ci && npm run build
```

## Architecture

Each language implements the same core abstractions:

| Concept | Description |
|---|---|
| **Algorithm** | rsa-pss-sha512, ecdsa-p256-sha256, ed25519, hmac-sha256 |
| **ComponentIdentifier** | Header name or derived component (@method, @path, etc.) with optional params |
| **SignatureParameters** | Components + keyId + created/expires/nonce/tag + optional algorithm |
| **SigningKey / VerifyingKey** | Interfaces wrapping crypto keys |
| **KeyProvider** | Resolves keyId to VerifyingKey |
| **Signer / Verifier** | Top-level sign and verify operations |
| **ContentDigest** | RFC 9530 SHA-256/SHA-512 digest |
| **SFV** | RFC 8941 Structured Field Values parser (subset) |

## HTTP Client Integrations

| Language | Integrations |
|---|---|
| Go | `Transport` (http.RoundTripper), `RequireSignature` (http.Handler middleware) |
| TypeScript | `createSigningFetch()`, `addSigningInterceptor()` (axios), `createSigningRequest()` (undici) |
| Java | `SigningInterceptor` (OkHttp), `HttpSigning` (JDK HttpClient), `SigningFilterFunction` (Spring WebClient) |
| Swift | `URLRequest.signed()` (URLSession), `SigningInterceptor` (Alamofire) |
| Kotlin | `SigningInterceptor` (OkHttp), `HttpSig` (Ktor client plugin) |

## Testing

- All implementations must pass the shared test vectors in `testdata/vectors/`.
- No mocks. Unit tests and integration tests only.
- Test vectors are derived from RFC 9421 Appendix B (7 test cases).
- Vector tests validate: signature base, signature input, deterministic signatures (HMAC/Ed25519), precomputed verify (RSA-PSS), round-trip sign/verify.
- Algorithm param in test vectors is for key selection only, NOT included as `alg=` in signature params.

## Cross-Language Gotchas

- **RSA key OID mismatch** (Java/Kotlin): Private key has RSASSA-PSS OID, public key has plain RSA OID. Try "RSA" KeyFactory first, fall back to "RSASSA-PSS".
- **EC P-256 key format** (Java/Kotlin): Test key file is SEC1 format, needs wrapping to PKCS#8 ASN.1 envelope for KeyFactory.
- **Ed25519 randomized signing** (Swift): Apple CryptoKit uses randomized Ed25519 for side-channel resistance. Signatures differ from Go/Java/Kotlin byte-for-byte. Round-trip verification always works.
- **ECDSA signature format**: RFC 9421 requires raw r||s (64 bytes), not DER. Java/Kotlin use `SHA256withECDSAinP1363Format`, Swift uses `rawRepresentation`, Go handles this in the algorithm layer.

## CI Workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| `go.yml` | push/PR to `golang/**` | Go tests |
| `typescript.yml` | push/PR to `typescript/**` | TypeScript tests |
| `java.yml` | push/PR to `java/**` | Java tests (JDK 17+21) |
| `swift.yml` | push/PR to `swift/**` | Swift tests (macOS) |
| `kotlin.yml` | push/PR to `kotlin/**` | Kotlin tests (JDK 17+21) |
| `docs.yml` | push/PR to `docs/**` | Docs build + GitHub Pages deploy |
| `cross-language.yml` | Weekly (Mon 6am UTC) | All 5 languages test suite |
| `release-*.yml` | Tag push (`go/v*`, `ts/v*`, etc.) | Release + publish |

## Release Tags

Convention: `{lang}/v{semver}` (e.g. `go/v1.0.0`, `ts/v1.0.0`, `java/v1.0.0`, `swift/v1.0.0`, `kotlin/v1.0.0`).

## Conventions

- Keep implementations independent. No shared code generation or cross-language tooling.
- Error types: use language-idiomatic error handling (Go errors, TS exceptions, Java exceptions, Swift enums, Kotlin exceptions).
- Each language's API should feel native to that ecosystem, not a transliteration.
- All public types that cross thread boundaries must be safe for concurrent use.
