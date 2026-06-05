---
sidebar_position: 2
---

# TypeScript

## Installation

```bash
npm install @zourzouvillys/httpsig
```

Requires Node.js 20 or later. The package is ESM-only.

## Quick Example: Sign a Request

```typescript
import { signMessage, signatureInputHeader, signatureHeader } from '@zourzouvillys/httpsig';
import { newKeyPair } from '@zourzouvillys/httpsig';
import { component } from '@zourzouvillys/httpsig';
import * as crypto from 'node:crypto';

// Create a key pair (auto-detects algorithm from key type)
const cryptoKp = crypto.generateKeyPairSync('ed25519');
const kp = newKeyPair('my-key-id', cryptoKp.privateKey);
const key = kp.signingKey;

// Build the message representation
const url = new URL('https://example.com/api/resource');
const msg = {
  isRequest: true,
  method: 'POST',
  url,
  headerValues(name: string): string[] {
    if (name === 'content-type') return ['application/json'];
    return [];
  },
};

// Sign
const result = await signMessage(msg, 'sig1', {
  components: [
    component('@method'),
    component('@path'),
    component('@authority'),
    component('content-type'),
  ],
  keyId: 'my-key-id',
  created: Math.floor(Date.now() / 1000),
}, key);

console.log('Signature-Input:', signatureInputHeader(result));
console.log('Signature:', signatureHeader(result));
```

Note that all sign and verify operations are `async` to support Web Crypto API backends.

## Quick Example: Verify a Signature

```typescript
import { verifyMessage } from '@zourzouvillys/httpsig';
import { newVerifyingKey } from '@zourzouvillys/httpsig';
import { component } from '@zourzouvillys/httpsig';
import type { KeyProvider } from '@zourzouvillys/httpsig';

// Set up a KeyProvider (auto-detects algorithm from key type)
const provider: KeyProvider = async (keyId, algorithm) => {
  const pub = await loadPublicKey(keyId);
  if (!pub) throw new Error(`unknown key: ${keyId}`);
  return newVerifyingKey(keyId, pub);
};

// Verify (msg has Signature and Signature-Input headers)
const result = await verifyMessage(msg, provider, {
  requiredComponents: [
    component('@method'),
    component('@authority'),
  ],
  maxAgeMs: 5 * 60 * 1000, // 5 minutes
});

console.log(`Verified: label=${result.label}, keyId=${result.keyId}`);
```

## HTTP Client Integrations

### fetch

```typescript
import { createSigningFetch } from '@zourzouvillys/httpsig/fetch';

const signedFetch = createSigningFetch({ key: myKey });
const response = await signedFetch('https://example.com/api', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ data: 'value' }),
});
```

### axios

```typescript
import axios from 'axios';
import { addSigningInterceptor } from '@zourzouvillys/httpsig/axios';

const client = axios.create({ baseURL: 'https://api.example.com' });
addSigningInterceptor(client, { key: myKey });

const response = await client.post('/resource', { data: 'value' });
```

### undici

```typescript
import { request } from 'undici';
import { createSigningRequest } from '@zourzouvillys/httpsig/undici';

const signedRequest = createSigningRequest(request, { key: myKey });
const { statusCode, body } = await signedRequest('https://example.com/api');
```

See the [Integrations Guide](/guides/integrations) for more details.

## Web Crypto API

For browser or edge runtimes, use the Web Crypto adapters:

```typescript
import { newWebCryptoSigningKey, newWebCryptoVerifyingKey } from '@zourzouvillys/httpsig';

const cryptoKey = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);

const signingKey = newWebCryptoSigningKey('my-key', cryptoKey.privateKey, 'ed25519');
const verifyingKey = newWebCryptoVerifyingKey('my-key', cryptoKey.publicKey, 'ed25519');
```
