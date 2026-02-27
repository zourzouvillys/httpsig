# httpsig - Swift

Swift implementation of [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) with [Content-Digest (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530) support.

## Install

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/zourzouvillys/httpsig.git", from: "0.1.0")
]
```

Three library targets are available:

```swift
.target(name: "MyApp", dependencies: [
    .product(name: "HTTPSig", package: "httpsig"),              // Core
    .product(name: "HTTPSigURLSession", package: "httpsig"),    // URLRequest signing
    .product(name: "HTTPSigAlamofire", package: "httpsig"),     // Alamofire adapter
])
```

Requires macOS 13+ / iOS 16+, Swift 6.0+.

## Usage

### Signing

```swift
import HTTPSig

let key = try Ed25519SigningKey(keyId: "my-key", pkcs8DER: keyData)

let params = SignatureParameters(
    components: [
        ComponentIdentifier("@method"),
        ComponentIdentifier("@authority"),
        ComponentIdentifier("content-type"),
    ],
    keyId: "my-key",
    created: Int64(Date().timeIntervalSince1970)
)

let result = try Signer.sign(msg: message, label: "sig1", params: params, key: key)

// Add headers
let sigInput = Signer.signatureInputHeader(result)
let sig = Signer.signatureHeader(result)
```

### Verification

```swift
import HTTPSig

struct MyKeyProvider: KeyProvider {
    func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? {
        return try Ed25519VerifyingKey(keyId: keyId, spkiDER: pubKeyData)
    }
}

let result = try Verifier.verify(
    msg: message,
    provider: MyKeyProvider(),
    options: VerifyOptions(maxAge: 300)
)
```

### URLSession Integration

```swift
import HTTPSigURLSession

var request = URLRequest(url: URL(string: "https://example.com/api")!)
request.httpMethod = "POST"
request.setValue("application/json", forHTTPHeaderField: "Content-Type")

let signed = try request.signed(label: "sig1", params: params, key: signingKey)
let (data, response) = try await URLSession.shared.data(for: signed)
```

For response verification:

```swift
let responseMsg = URLResponseMessage(response as! HTTPURLResponse)
let result = try Verifier.verify(msg: responseMsg, provider: keyProvider)
```

### Alamofire Integration

```swift
import HTTPSigAlamofire

let interceptor = SigningInterceptor(key: signingKey, label: "sig1", params: params)

let session = Session(interceptor: interceptor)
session.request("https://example.com/api").response { response in
    // request was signed automatically
}
```

## Key Management

### KeyPair (Recommended)

Static factory methods create a `KeyPair` bundling both signing and verifying keys:

```swift
let kp = KeyPair.ed25519(keyId: "my-key", privateKey: ed25519PrivateKey)
let kp = KeyPair.ecdsaP256(keyId: "my-key", privateKey: p256PrivateKey)
let kp = KeyPair.rsaPSS(keyId: "my-key", secKey: rsaSecKey)
let kp = KeyPair.hmacSHA256(keyId: "my-key", secret: sharedSecret)
```

### Secure Enclave

`SecureEnclaveSigningKey` wraps a `SecureEnclave.P256.Signing.PrivateKey` with a computed `verifyingKey`:

```swift
let seKey = SecureEnclave.P256.Signing.PrivateKey()
let signingKey = SecureEnclaveSigningKey(keyId: "se-key", privateKey: seKey)
// signingKey.verifyingKey is derived automatically
```

### Explicit Algorithm Constructors

| Algorithm | Signing Key | Verifying Key |
|---|---|---|
| RSA-PSS-SHA512 | `RSAPSSSigningKey(keyId:pkcs8DER:)` | `RSAPSSVerifyingKey(keyId:spkiDER:)` |
| ECDSA P-256 | `ECDSAP256SigningKey(keyId:derRepresentation:)` | `ECDSAP256VerifyingKey(keyId:derRepresentation:)` |
| Ed25519 | `Ed25519SigningKey(keyId:pkcs8DER:)` | `Ed25519VerifyingKey(keyId:spkiDER:)` |
| HMAC-SHA256 | `HMACSHA256Key(keyId:secret:)` | Same instance (symmetric) |

Crypto backends: CryptoKit for Ed25519, P-256, and HMAC. Security framework for RSA-PSS.

Apple CryptoKit Ed25519 uses randomized signing (for side-channel resistance), so signatures won't match other implementations byte-for-byte. Round-trip verification always works.

## Development

```bash
# Build
cd swift
swift build

# Run all tests
swift test

# Run only vector tests
swift test --filter VectorTests
```

### Project structure

```
swift/
  Package.swift
  Sources/
    HTTPSig/                    Core library
      Algorithm.swift           Algorithm enum
      ComponentIdentifier.swift Component with params
      Components.swift          Component extraction
      ContentDigest.swift       RFC 9530
      Errors.swift              HttpSigError enum
      HttpMessage.swift         HttpMessage protocol
      KeyProvider.swift         KeyProvider protocol
      Keys.swift                All key types + PEM utilities
      RawMessage.swift          Concrete message for testing
      SFV.swift                 Structured Field Values parser
      SignatureBase.swift       Signature base construction
      SignatureParameters.swift Signing parameters
      Signer.swift              Sign + header formatters
      SigningKey.swift          SigningKey protocol
      Verifier.swift            Verify + VerifyOptions/VerifyResult
      VerifyingKey.swift        VerifyingKey protocol
    HTTPSigURLSession/          URLRequest.signed() extension + URLResponseMessage
    HTTPSigAlamofire/           SigningInterceptor (Alamofire RequestInterceptor)
  Tests/
    HTTPSigTests/               Core tests + RFC 9421 vector tests
    HTTPSigURLSessionTests/     URLRequest signing tests
    HTTPSigAlamofireTests/      Alamofire interceptor tests
```

### Test vectors

Tests load shared vectors from `../../testdata/vectors/*.json` (path resolved via `#filePath`).

## License

Apache License 2.0.
