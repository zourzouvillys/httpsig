# Swift Implementation

## Build and Test

```bash
cd swift
swift build     # compile all targets
swift test      # run all tests
```

## Conventions

- Package: `HTTPSig` (SPM), macOS 13+ / iOS 16+, Swift 6.0+
- Swift 6 strict concurrency: all public types are `Sendable`
- `@preconcurrency import Security` for RSA-PSS (Security framework isn't fully Sendable-annotated)
- `SigningKey` / `VerifyingKey` / `KeyProvider` / `HttpMessage` are protocols
- `RawMessage` is a concrete struct with static factory methods `.request()` / `.response()`
- Headers stored as `[(String, String)]` tuples for multi-value support
- `SFVParams` is an ordered map (preserves parameter insertion order)
- `SFVParser` is a `~Copyable` struct (move-only, consumed during parsing)
- `Signer` / `Verifier` are enum namespaces (no instances)

## Crypto

- CryptoKit: Ed25519 (`Curve25519.Signing`), P-256 (`P256.Signing`), HMAC-SHA256
- Security framework: RSA-PSS via `SecKeyCreateSignature` / `SecKeyVerifySignature`
- Ed25519: Apple CryptoKit uses randomized signing (side-channel resistance). Signatures differ from Go/Java. Round-trip verification always works.
- ECDSA P-256: `sign()` uses raw r||s format (64 bytes) per RFC 9421, not DER
- RSA PKCS#8: manual ASN.1 unwrapping to extract PKCS#1 for Security framework

## Integration Modules

| Module | Target | Pattern |
|---|---|---|
| `HTTPSigURLSession` | `Sources/HTTPSigURLSession/` | `URLRequest.signed()` extension |
| `HTTPSigAlamofire` | `Sources/HTTPSigAlamofire/` | `SigningInterceptor: RequestInterceptor` |

`HTTPSigAlamofire` depends on `HTTPSigURLSession` (reuses `URLRequest.signed()`).

## Key files

| File | Purpose |
|---|---|
| `Signer.swift` | `Signer.sign()`, `signatureInputHeader()`, `signatureHeader()` |
| `Verifier.swift` | `Verifier.verify()`, `VerifyOptions`, `VerifyResult` |
| `Keys.swift` | All key types: Ed25519, ECDSA P-256, RSA-PSS, HMAC + PEM utilities |
| `SFV.swift` | Full RFC 8941 parser/serializer |
| `SignatureBase.swift` | Signature base construction |
| `Components.swift` | Derived component extraction |
| `VectorTests.swift` | Shared test vectors (Swift Testing framework) |
