# httpsig

[![Go](https://github.com/zourzouvillys/httpsig/actions/workflows/go.yml/badge.svg)](https://github.com/zourzouvillys/httpsig/actions/workflows/go.yml)
[![TypeScript](https://github.com/zourzouvillys/httpsig/actions/workflows/typescript.yml/badge.svg)](https://github.com/zourzouvillys/httpsig/actions/workflows/typescript.yml)
[![Java](https://github.com/zourzouvillys/httpsig/actions/workflows/java.yml/badge.svg)](https://github.com/zourzouvillys/httpsig/actions/workflows/java.yml)
[![Swift](https://github.com/zourzouvillys/httpsig/actions/workflows/swift.yml/badge.svg)](https://github.com/zourzouvillys/httpsig/actions/workflows/swift.yml)
[![Kotlin](https://github.com/zourzouvillys/httpsig/actions/workflows/kotlin.yml/badge.svg)](https://github.com/zourzouvillys/httpsig/actions/workflows/kotlin.yml)

Multi-language [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) library with [Content-Digest (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530) support.

## Languages

| Language | Package | Integrations |
|---|---|---|
| [Go](golang/) | `go get github.com/zourzouvillys/httpsig/golang` | net/http middleware |
| [TypeScript](typescript/) | `npm install @zourzouvillys/httpsig` | fetch, axios, undici |
| [Java](java/) | `com.zourzouvillys:httpsig` | OkHttp, JDK HttpClient, Spring WebClient |
| [Swift](swift/) | SPM: `github.com/zourzouvillys/httpsig` | URLSession, Alamofire |
| [Kotlin](kotlin/) | `com.zourzouvillys:httpsig-kotlin` | OkHttp, Ktor |

## Features

- Full RFC 9421 implementation: signing and verification
- Content-Digest support (RFC 9530)
- All standard algorithms: RSA-PSS-SHA512, ECDSA-P256-SHA256, Ed25519, HMAC-SHA256
- Non-extractable key support: HSM, Secure Enclave, Android Keystore, Web Crypto API
- HTTP client integrations for each language
- Shared test vectors across all implementations (RFC 9421 Appendix B)

## Quick Start

### Go

```go
import "github.com/zourzouvillys/httpsig/golang"

key, _ := httpsig.NewEd25519SigningKey("my-key-id", privateKey)

params := httpsig.SignatureParameters{
    Components: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@authority"),
        httpsig.Component("content-type"),
    },
    Created: httpsig.Int64Ptr(time.Now().Unix()),
}

sig, _ := httpsig.SignMessage(msg, "sig1", params, key)
```

### TypeScript

```typescript
import { signMessage, Algorithm } from '@zourzouvillys/httpsig';

const result = await signMessage(message, 'sig1', {
  components: ['@method', '@authority', 'content-type'],
  keyId: 'my-key-id',
  created: Math.floor(Date.now() / 1000),
}, signingKey);
```

### Java

```java
var params = SignatureParameters.builder()
    .component("@method")
    .component("@authority")
    .component("content-type")
    .keyId("my-key-id")
    .created(Instant.now())
    .build();

var result = Signer.sign(message, "sig1", params, signingKey, null);
```

### Swift

```swift
let params = SignatureParameters(
    components: [ComponentIdentifier("@method"), ComponentIdentifier("@authority")],
    keyId: "my-key-id",
    created: Int64(Date().timeIntervalSince1970)
)

let result = try Signer.sign(msg: message, label: "sig1", params: params, key: signingKey)
```

### Kotlin

```kotlin
val params = SignatureParameters.builder()
    .component("@method")
    .component("@authority")
    .component("content-type")
    .keyId("my-key-id")
    .created(Instant.now())
    .build()

val result = Signer.sign(message, "sig1", params, signingKey)
```

## Documentation

Full documentation is available at the [docs site](https://zourzouvillys.github.io/httpsig/), including getting started guides, concept explanations, and integration walkthroughs.

## License

Apache License 2.0. See [LICENSE](LICENSE).
