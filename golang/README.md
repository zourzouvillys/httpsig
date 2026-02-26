# httpsig (Go)

Go implementation of [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) with [Content-Digest (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530) support.

Works on both sides of the wire: clients sign outgoing requests and verify incoming responses, servers verify incoming requests and sign outgoing responses.

## Install

```bash
go get github.com/zourzouvillys/httpsig/golang
```

Requires Go 1.22+.

## Algorithms

| Algorithm | Constant | Deterministic |
|---|---|---|
| RSA-PSS using SHA-512 | `AlgorithmRSAPSSSHA512` | No |
| ECDSA P-256 using SHA-256 | `AlgorithmECDSAP256SHA256` | No |
| Ed25519 | `AlgorithmEd25519` | Yes |
| HMAC-SHA256 | `AlgorithmHMACSHA256` | Yes |

## Client: Signing a Request

```go
package main

import (
    "crypto/ed25519"
    "fmt"
    "net/http"
    "time"

    "github.com/zourzouvillys/httpsig/golang"
)

func main() {
    // Load or generate your key
    _, privKey, _ := ed25519.GenerateKey(nil)
    key := httpsig.NewEd25519SigningKey("my-key-id", privKey)

    // Build the request
    req, _ := http.NewRequest("POST", "https://example.com/api", nil)
    req.Header.Set("Content-Type", "application/json")

    // Define what to sign
    params := httpsig.SignatureParameters{
        Components: []httpsig.ComponentIdentifier{
            httpsig.Component("@method"),
            httpsig.Component("@path"),
            httpsig.Component("@authority"),
            httpsig.Component("content-type"),
        },
        KeyID:   "my-key-id",
        Created: httpsig.Int64Ptr(time.Now().Unix()),
    }

    // Sign
    msg := &httpsig.RequestMessage{Req: req}
    result, err := httpsig.SignMessage(msg, "sig1", params, key, nil)
    if err != nil {
        panic(err)
    }

    // Apply headers
    req.Header.Set("Signature-Input", httpsig.SignatureInputHeader(result))
    req.Header.Set("Signature", httpsig.SignatureHeader(result))

    fmt.Println("Signature-Input:", req.Header.Get("Signature-Input"))
}
```

## Server: Verifying a Request

```go
// Define a key provider that resolves keyId -> VerifyingKey
provider := httpsig.KeyProvider(func(keyID string, alg httpsig.Algorithm) (httpsig.VerifyingKey, error) {
    if keyID == "my-key-id" {
        return httpsig.NewEd25519VerifyingKey(keyID, pubKey), nil
    }
    return nil, httpsig.ErrKeyNotFound
})

// Verify with options
msg := &httpsig.RequestMessage{Req: req}
result, err := httpsig.VerifyMessage(msg, provider, &httpsig.VerifyOptions{
    MaxAge: 5 * time.Minute,
    RequiredComponents: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@authority"),
    },
}, nil)
if err != nil {
    // signature invalid, missing, or expired
}
fmt.Printf("Verified: label=%s keyId=%s\n", result.Label, result.KeyID)
```

## Server: Signing a Response

Response signatures can reference components from the original request using `;req`.

```go
// Sign a response, binding it to the request
respMsg := &httpsig.ResponseMessage{Resp: resp, Req: req}

params := httpsig.SignatureParameters{
    Components: []httpsig.ComponentIdentifier{
        httpsig.Component("@status"),
        httpsig.Component("content-type"),
        httpsig.Component("content-digest"),
        httpsig.ComponentReq("@method"),    // @method from the request
        httpsig.ComponentReq("@authority"), // @authority from the request
    },
    KeyID:   "server-key",
    Created: httpsig.Int64Ptr(time.Now().Unix()),
}

result, err := httpsig.SignMessage(respMsg, "sig1", params, serverKey, nil)
```

## Client: Verifying a Response

```go
respMsg := &httpsig.ResponseMessage{Resp: resp, Req: req}

result, err := httpsig.VerifyMessage(respMsg, provider, &httpsig.VerifyOptions{
    RequiredComponents: []httpsig.ComponentIdentifier{
        httpsig.Component("@status"),
    },
}, req) // pass the original request for ;req component resolution
```

## Key Types

Constructors for all supported algorithms:

```go
// Asymmetric keys
httpsig.NewRSAPSSSigningKey(keyID, rsaPrivateKey)
httpsig.NewRSAPSSVerifyingKey(keyID, rsaPublicKey)

httpsig.NewECDSAP256SigningKey(keyID, ecdsaPrivateKey)
httpsig.NewECDSAP256VerifyingKey(keyID, ecdsaPublicKey)

httpsig.NewEd25519SigningKey(keyID, ed25519PrivateKey)
httpsig.NewEd25519VerifyingKey(keyID, ed25519PublicKey)

// Symmetric (implements both SigningKey and VerifyingKey)
httpsig.NewHMACSHA256Key(keyID, sharedSecret)

// HSM / PKCS#11 (any crypto.Signer)
httpsig.NewSignerKey(keyID, algorithm, cryptoSigner)
```

## Component Identifiers

Derived components:

```go
httpsig.Component("@method")         // HTTP method
httpsig.Component("@path")           // URL path
httpsig.Component("@query")          // query string (with leading ?)
httpsig.Component("@authority")      // host[:port]
httpsig.Component("@scheme")         // url scheme
httpsig.Component("@target-uri")     // full request URI
httpsig.Component("@request-target") // path?query
httpsig.Component("@status")         // response status code
```

Header fields and parameterized components:

```go
httpsig.Component("content-type")       // header value
httpsig.QueryParam("page")              // @query-param;name="page"
httpsig.ComponentReq("content-type")    // content-type;req (from request on response sigs)
httpsig.ComponentWithParams("example-dict", params) // with ;sf, ;bs, ;key
```

## Content-Digest (RFC 9530)

```go
// Compute
header, _ := httpsig.ContentDigest(body, httpsig.DigestSHA256)
// "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:"

// Verify
ok, _ := httpsig.VerifyContentDigest(body, req.Header.Get("Content-Digest"))
```

## Signature Base

For custom flows, you can build the signature base directly:

```go
base, sigInputValue, err := httpsig.BuildSignatureBase(msg, params, nil)
// base contains the raw bytes to sign
// sigInputValue is the serialized signature parameters
```

## Signature Parameters

```go
params := httpsig.SignatureParameters{
    Components: components,
    KeyID:      "my-key",
    Created:    httpsig.Int64Ptr(time.Now().Unix()),
    Expires:    httpsig.Int64Ptr(time.Now().Add(5 * time.Minute).Unix()),
    Nonce:      httpsig.StringPtr("unique-nonce"),
    Tag:        httpsig.StringPtr("my-app"),
    Algorithm:  httpsig.AlgorithmEd25519, // optional: include "alg" in params
}
```

The `Algorithm` field controls whether `alg` appears in the serialized signature parameters. Leave it empty to omit (the signing key determines which algorithm is used regardless).

## Verify Options

```go
opts := &httpsig.VerifyOptions{
    RequiredComponents: []httpsig.ComponentIdentifier{...}, // must be covered
    MaxAge:             5 * time.Minute,                     // max age from "created"
    RejectExpired:      &rejectExpired,                      // check "expires" (default: true)
    RequiredLabel:      "sig1",                              // verify specific label
    Now:                func() time.Time { ... },            // override clock
}
```

## License

Apache License 2.0.
