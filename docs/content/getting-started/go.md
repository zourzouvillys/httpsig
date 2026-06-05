---
sidebar_position: 1
---

# Go

## Installation

```bash
go get github.com/zourzouvillys/httpsig/golang
```

Requires Go 1.22 or later. The package name is `httpsig`.

## Quick Example: Sign a Request

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
    // Load or generate your private key
    _, privateKey, _ := ed25519.GenerateKey(nil)

    // Create a key pair (auto-detects algorithm from key type)
    kp, _ := httpsig.NewKeyPair("my-key-id", privateKey)
    key := kp.Signing

    // Build a request
    req, _ := http.NewRequest("POST", "https://example.com/api/resource", nil)
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

    // Sign it
    msg := &httpsig.RequestMessage{Req: req}
    result, err := httpsig.SignMessage(msg, "sig1", params, key, nil)
    if err != nil {
        panic(err)
    }

    // Apply signature headers
    req.Header.Set("Signature-Input", httpsig.SignatureInputHeader(result))
    req.Header.Set("Signature", httpsig.SignatureHeader(result))

    fmt.Println("Signature-Input:", req.Header.Get("Signature-Input"))
}
```

## Quick Example: Verify a Signature

```go
package main

import (
    "crypto/ed25519"
    "fmt"
    "time"

    "github.com/zourzouvillys/httpsig/golang"
)

func main() {
    // Load the public key
    publicKey := loadPublicKey() // your public key

    // Set up a KeyProvider (auto-detects algorithm from public key type)
    provider := func(keyID string, alg httpsig.Algorithm) (httpsig.VerifyingKey, error) {
        if keyID == "my-key-id" {
            return httpsig.NewVerifyingKeyFromPublic(keyID, publicKey)
        }
        return nil, fmt.Errorf("unknown key: %s", keyID)
    }

    // Verify the message (msg is an httpsig.Message with Signature and Signature-Input headers)
    result, err := httpsig.VerifyMessage(msg, provider, &httpsig.VerifyOptions{
        RequiredComponents: []httpsig.ComponentIdentifier{
            httpsig.Component("@method"),
            httpsig.Component("@authority"),
        },
        MaxAge: 5 * time.Minute,
    }, nil)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Verified signature %q signed by key %q\n", result.Label, result.KeyID)
}
```

## HTTP Client Integration

The `Transport` type wraps any `http.RoundTripper` to sign outgoing requests automatically:

```go
client := &http.Client{
    Transport: &httpsig.Transport{
        Key: signingKey,
        // Optionally customize what gets signed per-request:
        // Params: func(req *http.Request) httpsig.SignatureParameters { ... },
    },
}

// Every request made with this client will be signed
resp, err := client.Get("https://example.com/api/resource")
```

For server-side verification, use `RequireSignature` middleware:

```go
handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("authenticated!"))
})

protected := httpsig.RequireSignature(keyProvider, &httpsig.VerifyOptions{
    RequiredComponents: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@authority"),
    },
})(handler)

http.ListenAndServe(":8080", protected)
```

See the [Integrations Guide](/guides/integrations) for more details.
