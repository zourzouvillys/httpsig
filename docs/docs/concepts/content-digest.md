---
sidebar_position: 5
---

# Content-Digest

[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) defines the `Content-Digest` header, which provides integrity protection for the message body. When combined with HTTP Message Signatures, you get end-to-end body integrity: the signature covers the `content-digest` header, which in turn covers the body.

## How It Works

1. Compute the hash of the request or response body.
2. Set the `Content-Digest` header with the hash value.
3. Include `"content-digest"` in the signature's covered components.
4. The verifier checks the signature (which covers `Content-Digest`), then separately verifies that the `Content-Digest` value matches the actual body.

```
                   signs
Signature ---------> Content-Digest ---------> Body
                                     hashes
```

## Supported Algorithms

| Algorithm  | Hash     | Output Size |
|------------|----------|-------------|
| `sha-256`  | SHA-256  | 32 bytes    |
| `sha-512`  | SHA-512  | 64 bytes    |

## Header Format

The `Content-Digest` header uses the Structured Field Values byte sequence format:

```
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
```

## Computing a Content-Digest

### Go

```go
import "github.com/zourzouvillys/httpsig/golang"

body := []byte(`{"hello": "world"}`)
digest, err := httpsig.ContentDigest(body, httpsig.DigestSHA256)
// digest = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"
```

### TypeScript

```typescript
import { contentDigest } from '@zourzouvillys/httpsig';

const body = new TextEncoder().encode('{"hello": "world"}');
const digest = contentDigest(body, 'sha-256');
```

### Java

```java
import com.zourzouvillys.httpsig.ContentDigest;

byte[] body = "{\"hello\": \"world\"}".getBytes();
String digest = ContentDigest.compute(body, "sha-256");
```

## Verifying a Content-Digest

### Go

```go
body := []byte(`{"hello": "world"}`)
headerValue := response.Header.Get("Content-Digest")

valid, err := httpsig.VerifyContentDigest(body, headerValue)
if !valid {
    // body has been tampered with
}
```

### TypeScript

```typescript
import { verifyContentDigest } from '@zourzouvillys/httpsig';

const valid = verifyContentDigest(body, headerValue);
```

## Using with Signatures

To get full body integrity, include `content-digest` in your signature components:

```go
params := httpsig.SignatureParameters{
    Components: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@path"),
        httpsig.Component("@authority"),
        httpsig.Component("content-type"),
        httpsig.Component("content-digest"),
    },
    KeyID:   "my-key-id",
    Created: httpsig.Int64Ptr(time.Now().Unix()),
}

// First, set the Content-Digest header on the request
digest, _ := httpsig.ContentDigest(body, httpsig.DigestSHA256)
req.Header.Set("Content-Digest", digest)

// Then sign (the signature will cover the Content-Digest value)
result, _ := httpsig.SignMessage(msg, "sig1", params, key, nil)
```

The verifier then performs two checks:

1. Verify the signature (which proves `Content-Digest` has not been tampered with).
2. Verify the `Content-Digest` matches the actual body (which proves the body has not been tampered with).

This two-step process is intentional: the signature algorithm and the digest algorithm are independent, and the verifier can use different policies for each.
