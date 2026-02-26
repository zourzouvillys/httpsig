# httpsig - TypeScript

TypeScript implementation of [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) with [Content-Digest (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530) support.

## Install

```bash
npm install @zourzouvillys/httpsig
```

Requires Node.js 20+. ESM-only.

## Usage

### Signing

```typescript
import { signMessage, signatureInputHeader, signatureHeader } from '@zourzouvillys/httpsig';
import { newEd25519SigningKey } from '@zourzouvillys/httpsig';

const key = newEd25519SigningKey('my-key-id', privateKeyObject);

const result = await signMessage(message, 'sig1', {
  components: [
    { name: '@method' },
    { name: '@authority' },
    { name: 'content-type' },
  ],
  keyId: 'my-key-id',
  created: Math.floor(Date.now() / 1000),
}, key);

// Add headers to request
headers.set('Signature-Input', signatureInputHeader(result));
headers.set('Signature', signatureHeader(result));
```

### Verification

```typescript
import { verifyMessage } from '@zourzouvillys/httpsig';

const provider = async (keyId: string) => {
  return newEd25519VerifyingKey(keyId, publicKeyObject);
};

const result = await verifyMessage(message, provider, {
  maxAge: 300, // 5 minutes
  requiredComponents: [{ name: '@method' }],
});
```

### Integrations

#### fetch

```typescript
import { createSigningFetch } from '@zourzouvillys/httpsig/fetch';

const signedFetch = createSigningFetch({ key: myKey });
const response = await signedFetch('https://example.com/api', { method: 'POST' });
```

#### axios

```typescript
import { addSigningInterceptor } from '@zourzouvillys/httpsig/axios';

addSigningInterceptor(axiosInstance, {
  key: myKey,
  params: (config) => ({
    components: [{ name: '@method' }, { name: '@authority' }],
    keyId: 'my-key',
    created: Math.floor(Date.now() / 1000),
  }),
});
```

#### undici

```typescript
import { createSigningRequest } from '@zourzouvillys/httpsig/undici';

const req = createSigningRequest('https://example.com/api', {
  method: 'POST',
  key: myKey,
});
```

## Algorithms

| Algorithm | Constructor |
|---|---|
| RSA-PSS-SHA512 | `newRSAPSSSigningKey(keyId, keyObject)` |
| ECDSA P-256 SHA-256 | `newECDSAP256SigningKey(keyId, keyObject)` |
| Ed25519 | `newEd25519SigningKey(keyId, keyObject)` |
| HMAC-SHA256 | `newHMACSHA256Key(keyId, secret)` |

All key constructors accept `node:crypto` `KeyObject` instances (or `Uint8Array` for HMAC).

Sign/verify APIs are `async` to support future Web Crypto API integration.

## Development

```bash
# Install dependencies
npm ci

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Type check
npm run lint

# Build
npm run build

# Clean
npm run clean
```

### Project structure

```
typescript/
  src/
    index.ts             Barrel export
    algorithm.ts         Algorithm operations (node:crypto)
    base.ts              Signature base construction
    components.ts        Component extraction
    digest.ts            Content-Digest (RFC 9530)
    errors.ts            Error types
    keys.ts              Key constructors
    message.ts           RawMessage implementation
    sfv.ts               Structured Field Values parser/serializer
    signer.ts            signMessage, signatureInputHeader, signatureHeader
    types.ts             TypeScript interfaces and types
    verifier.ts          verifyMessage
    integrations/
      fetch.ts           createSigningFetch
      axios.ts           addSigningInterceptor
      undici.ts          createSigningRequest
  test/
    *.test.ts            Tests (vitest)
```

### Test vectors

Tests load shared vectors from `../testdata/vectors/*.json`.

## License

Apache License 2.0.
