# Go Implementation

## Build and Test

```bash
cd golang
go test -race ./...    # all tests with race detector
go vet ./...           # static analysis
```

## Conventions

- Package: `httpsig`
- Module path: `github.com/zourzouvillys/httpsig/golang`
- Go 1.22+, zero external dependencies
- `KeyProvider` is a function type: `func(keyID string, algorithm Algorithm) (VerifyingKey, error)`
- `NewKeyPair()` auto-detects algorithm from `crypto.PrivateKey`; `NewHMACKeyPair()` for symmetric
- `NewSigningKeyFromSigner()` / `NewVerifyingKeyFromPublic()` auto-detect algorithm from key type
- `KeyPair` struct bundles `Signing` + `Verifying` keys with `KeyID()` and `Algorithm()`
- `NewSignerKey()` supports `crypto.Signer` for HSM/PKCS#11 backends (prefer `NewSigningKeyFromSigner` when algorithm can be inferred)
- Errors use sentinel values: `ErrMissingSignature`, `ErrInvalidSignature`, `ErrKeyNotFound`, `ErrSignatureFutureDated`, `ErrAlgorithmMismatch`, etc.
- `VerifyOptions.MaxClockSkew` rejects future-dated `created` timestamps
- Verifier checks `alg` parameter against resolved key's `Algorithm()` and returns key-derived values in `VerifyResult`
- Tests are `*_test.go` files alongside source (standard Go convention)
- `vector_test.go` loads shared vectors from `../testdata/vectors/*.json`
- `Int64Ptr()` / `StringPtr()` helper functions for optional fields in `SignatureParameters`

## Architecture

- `SignMessage()` / `VerifyMessage()` are the top-level API
- `BuildSignatureBase()` is available for custom flows
- `Transport` wraps `http.RoundTripper` for client-side signing
- `VerifyMiddleware` / `RequireSignature` wrap `http.Handler` for server-side verification
- `RequestMessage` / `ResponseMessage` adapt `*http.Request` / `*http.Response` to `Message`
- SFV parser handles the RFC 8941 subset needed for signatures
- Algorithm implementations: `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/hmac`

## Key files

| File | Purpose |
|---|---|
| `signer.go` | `SignMessage()`, `SignatureInputHeader()`, `SignatureHeader()` |
| `verifier.go` | `VerifyMessage()`, `VerifyOptions` |
| `key.go` | All key constructors and interfaces |
| `transport.go` | Signing `http.RoundTripper` |
| `middleware.go` | Verification `http.Handler` middleware |
| `base.go` | Signature base construction |
| `components.go` | Derived component extraction |
| `sfv.go` | RFC 8941 Structured Field Values parser/serializer |
