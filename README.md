# httpsig

Multi-language [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) library.

## Languages

| Language | Directory | Package | Status |
|---|---|---|---|
| Go | [`golang/`](golang/) | `github.com/zourzouvillys/httpsig/golang` | In progress |
| TypeScript | [`typescript/`](typescript/) | `@zourzouvillys/httpsig` | Planned |
| Java | [`java/`](java/) | `com.zourzouvillys:httpsig` | Planned |
| Swift | [`swift/`](swift/) | `HTTPSig` | Planned |
| Kotlin | [`kotlin/`](kotlin/) | `com.zourzouvillys:httpsig` | Planned |

## Features

- Full RFC 9421 implementation: signing and verification
- Content-Digest support (RFC 9530)
- All standard algorithms: RSA-PSS-SHA512, ECDSA-P256-SHA256, Ed25519, HMAC-SHA256
- Non-extractable key support: HSM, Secure Enclave, Android Keystore, Web Crypto API
- HTTP client integrations per language (net/http, fetch, OkHttp, URLSession, Ktor, etc.)
- Shared test vectors across all implementations

## Quick Start (Go)

```go
import "github.com/zourzouvillys/httpsig/golang"

// Create a signing key
key, _ := httpsig.NewEd25519SigningKey("my-key-id", privateKey)

// Sign a request
params := httpsig.SignatureParameters{
    Components: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@path"),
        httpsig.Component("@authority"),
        httpsig.Component("content-type"),
    },
    Created: httpsig.Int64Ptr(time.Now().Unix()),
}

sig, _ := httpsig.SignMessage(msg, "sig1", params, key)
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
