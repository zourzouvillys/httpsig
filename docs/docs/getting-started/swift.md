---
sidebar_position: 4
---

# Swift

## Installation

### Swift Package Manager

Add the dependency to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/zourzouvillys/httpsig", from: "0.1.0"),
]
```

Then add the targets you need:

```swift
.target(
    name: "YourApp",
    dependencies: [
        .product(name: "HTTPSig", package: "httpsig"),
        .product(name: "HTTPSigURLSession", package: "httpsig"),       // URLRequest signing
        .product(name: "HTTPSigAlamofire", package: "httpsig"),        // Alamofire interceptor
    ]
),
```

Requires Swift 6.0+, macOS 13+ / iOS 16+.

The crypto implementation uses CryptoKit for Ed25519, ECDSA P-256, and HMAC, and the Security framework for RSA-PSS.

## Quick Example: Sign a Request

```swift
import HTTPSig
import CryptoKit

// Create a key pair (static factory per algorithm)
let privateKey = Curve25519.Signing.PrivateKey()
let kp = KeyPair.ed25519(keyId: "my-key-id", privateKey: privateKey)
let key = kp.signingKey

// Build signature parameters
let params = SignatureParameters(
    components: [
        .init("@method"),
        .init("@path"),
        .init("@authority"),
        .init("content-type"),
    ],
    keyId: "my-key-id",
    created: Int64(Date().timeIntervalSince1970)
)

// Sign a message
let result = try Signer.sign(msg: httpMessage, label: "sig1", params: params, key: key)

// Apply signature headers
request.addValue(
    Signer.signatureInputHeader(result),
    forHTTPHeaderField: "Signature-Input"
)
request.addValue(
    Signer.signatureHeader(result),
    forHTTPHeaderField: "Signature"
)
```

## Quick Example: Verify a Signature

```swift
import HTTPSig
import CryptoKit

// Set up a KeyProvider
struct MyKeyProvider: KeyProvider {
    let publicKey: Curve25519.Signing.PublicKey

    func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? {
        if keyId == "my-key-id" {
            return Ed25519VerifyingKey(keyId: keyId, publicKey: publicKey)
        }
        return nil
    }
}

let provider = MyKeyProvider(publicKey: publicKey)

let result = try Verifier.verify(
    msg: httpMessage,
    provider: provider,
    options: VerifyOptions(
        requiredComponents: [.init("@method"), .init("@authority")],
        maxAge: 300 // 5 minutes
    )
)

print("Verified: label=\(result.label), keyId=\(result.keyId)")
```

## HTTP Client Integrations

### URLSession

The `HTTPSigURLSession` module adds a `signed()` extension to `URLRequest`:

```swift
import HTTPSigURLSession

var request = URLRequest(url: URL(string: "https://example.com/api")!)
request.httpMethod = "POST"
request.setValue("application/json", forHTTPHeaderField: "Content-Type")

let signed = try request.signed(label: "sig1", params: params, key: signingKey)
let (data, response) = try await URLSession.shared.data(for: signed)
```

### Alamofire

The `HTTPSigAlamofire` module provides a `SigningInterceptor` that conforms to Alamofire's `RequestInterceptor`:

```swift
import Alamofire
import HTTPSigAlamofire

let interceptor = SigningInterceptor(key: signingKey, label: "sig1", params: params)

let session = Session(interceptor: interceptor)
let response = await session.request("https://example.com/api").serializingData().response
```

See the [Integrations Guide](/docs/guides/integrations) for more details.

## Secure Enclave

On Apple platforms, use `SecureEnclaveSigningKey` for hardware-backed P-256 keys:

```swift
import HTTPSig
import CryptoKit

let seKey = SecureEnclave.P256.Signing.PrivateKey()
let signingKey = SecureEnclaveSigningKey(keyId: "se-key", privateKey: seKey)
// The verifying key is derived automatically from the Secure Enclave key
```

## Notes

Apple CryptoKit uses randomized Ed25519 signing for side-channel resistance. This means Ed25519 signatures produced by Swift will differ from those produced by Go, Java, or other implementations for the same input. Round-trip verification always works correctly.
