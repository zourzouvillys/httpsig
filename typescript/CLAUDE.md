# TypeScript Implementation

## Build and Test

```bash
cd typescript
npm ci                  # install dependencies
npm test                # run tests (vitest)
npm run lint            # type check (tsc --noEmit)
npm run build           # compile to dist/
```

## Conventions

- Package: `@zourzouvillys/httpsig`, ESM-only
- Node.js 20+, zero runtime dependencies (axios is an optional peer dep)
- All sign/verify APIs are `async` (returns `Promise`) for future Web Crypto compatibility
- `newKeyPair()` / `newSigningKey()` / `newVerifyingKey()` auto-detect algorithm from `KeyObject`
- `KeyPair` interface bundles `signingKey` + `verifyingKey` with `keyId` and `algorithm`
- `newWebCryptoSigningKey()` / `newWebCryptoVerifyingKey()` adapt Web Crypto `CryptoKey` (algorithm must be specified)
- Key constructors use `node:crypto` `KeyObject` instances
- `SignatureParameters` is a plain object: `{ components, keyId, created, expires, nonce, tag }`
- `ComponentIdentifier` is `{ name: string; params?: Record<string, string | boolean> }`
- `KeyProvider` is `(keyId: string, algorithm?: string) => Promise<VerifyingKey | null>`
- `VerifyOptions.maxClockSkewMs` rejects future-dated `created` timestamps
- Verifier checks `alg` parameter against resolved key's `algorithm` and returns key-derived values in `VerifyResult`
- Integration sub-paths: `@zourzouvillys/httpsig/fetch`, `/axios`, `/undici`
- Tests use vitest, files at `test/*.test.ts`
- `vector.test.ts` loads shared vectors from `../testdata/vectors/*.json`

## Architecture

- `signMessage()` / `verifyMessage()` are the top-level async API
- `buildSignatureBase()` available for custom flows
- `createSigningFetch()` wraps the global `fetch` with signing
- `addSigningInterceptor()` adds an axios request interceptor
- `createSigningRequest()` creates signed undici requests
- SFV parser handles RFC 8941 subset (dictionary, inner list, items, parameters)
- Algorithms use `node:crypto`: `sign`/`verify` for asymmetric, `createHmac` for HMAC

## Key files

| File | Purpose |
|---|---|
| `signer.ts` | `signMessage()`, `signatureInputHeader()`, `signatureHeader()` |
| `verifier.ts` | `verifyMessage()` |
| `keys.ts` | Key constructors for all algorithms |
| `types.ts` | All interfaces: `SigningKey`, `VerifyingKey`, `HttpMessage`, etc. |
| `integrations/fetch.ts` | `createSigningFetch()` |
| `integrations/axios.ts` | `addSigningInterceptor()` |
| `integrations/undici.ts` | `createSigningRequest()` |
