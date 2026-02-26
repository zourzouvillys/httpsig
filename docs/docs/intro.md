---
sidebar_position: 1
slug: /intro
---

# Introduction

**httpsig** is a multi-language library that implements [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) and [Content-Digest (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530).

## What Problem Does It Solve?

HTTP requests and responses travel through proxies, CDNs, and load balancers. Standard TLS protects the transport layer, but it does not guarantee that the message content has not been tampered with after decryption, and it does not provide a non-repudiable proof of who sent the message.

HTTP Message Signatures solve this by cryptographically signing specific parts of an HTTP message (the method, path, headers, and other components). The recipient can verify the signature to confirm:

- **Integrity**: the signed components have not been modified in transit.
- **Authentication**: the message was signed by the holder of the private key.
- **Non-repudiation**: the signer cannot later deny having signed the message (with asymmetric algorithms).

## Supported Languages

| Language   | Package                                  | Integrations |
|------------|------------------------------------------|--------------|
| Go         | `github.com/zourzouvillys/httpsig/golang`| net/http (RoundTripper + Handler middleware) |
| TypeScript | `@zourzouvillys/httpsig`                 | fetch, axios, undici |
| Java       | `io.zrz:httpsig`              | OkHttp, JDK HttpClient, Spring WebClient |
| Swift      | `HTTPSig` (SPM)                          | URLSession, Alamofire |
| Kotlin     | `io.zrz:httpsig-kotlin`       | OkHttp, Ktor |

All five implementations share the same test vectors derived from RFC 9421 Appendix B, ensuring cross-language interoperability.

## Supported Algorithms

- **rsa-pss-sha512** -- RSA Probabilistic Signature Scheme with SHA-512
- **ecdsa-p256-sha256** -- ECDSA on the NIST P-256 curve with SHA-256
- **ed25519** -- Edwards-curve Digital Signature Algorithm
- **hmac-sha256** -- HMAC with SHA-256 (symmetric)

## Key Features

- Full RFC 9421 signature base construction and verification
- Content-Digest generation and verification (RFC 9530, SHA-256 and SHA-512)
- All standard derived components: `@method`, `@path`, `@authority`, `@query`, `@query-param`, `@status`, `@scheme`, `@target-uri`, `@request-target`
- Header field signing with `;sf`, `;bs`, `;key`, and `;req` parameters
- Non-extractable key support: HSM/PKCS#11, Apple Secure Enclave, Android Keystore, Web Crypto API
- HTTP client integrations for each language (middleware, interceptors, filter functions)
- Verification security: algorithm consistency checks, future-dated signature rejection (`maxClockSkew`), replay protection via `maxAge` and `expires`

## Next Steps

- Pick your language and follow the [Getting Started](/docs/getting-started/go) guide
- Read [How It Works](/docs/concepts/how-it-works) for the theory behind RFC 9421
- See the [Signing Guide](/docs/guides/signing) for end-to-end examples
