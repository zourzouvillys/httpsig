---
sidebar_position: 1
slug: /
---

# HTTP Message Signatures for Every Platform

**httpsig** is a multi-language library implementing [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421) and [Content-Digest (RFC 9530)](https://www.rfc-editor.org/rfc/rfc9530). It provides cryptographic proof of who sent an HTTP message and that it has not been tampered with -- per-request, without shared secrets or bearer tokens.

## Why Sign Every Request?

Most web authentication today relies on **bearer tokens**: session cookies, JWTs, OAuth access tokens, or API keys. A bearer token grants access to whoever holds it. If an attacker obtains the token -- through XSS, a compromised log, a leaked database, a man-in-the-middle on internal traffic, or a browser extension exfiltrating cookies -- they can use it to perform any operation the legitimate user could, from any device, until the token expires or is revoked.

HTTP Message Signatures take a fundamentally different approach: **instead of proving you once held a credential, you prove you hold a private key right now, for this specific request.**

### The Problem with Bearer Tokens

Bearer tokens -- session cookies, JWTs, API keys -- are secrets that travel with every request. Anyone who intercepts, copies, or exfiltrates the token becomes indistinguishable from the legitimate user.

**How tokens get stolen:**

- **Cross-site scripting (XSS):** Malicious JavaScript reads `document.cookie` or pulls tokens from `localStorage` and sends them to an attacker-controlled server.
- **Compromised infrastructure:** A proxy, CDN, or logging system inadvertently records an `Authorization` header or cookie. An attacker with access to those logs can extract and replay the tokens.
- **Token leakage through URLs:** Tokens passed in query strings end up in browser history, referrer headers, and server access logs.
- **Man-in-the-middle on internal traffic:** TLS terminates at a load balancer or service mesh proxy. Between that termination point and the backend, tokens travel in cleartext.
- **Browser extensions and malware:** Malicious browser extensions have full access to cookies and request headers for every site the user visits.
- **Supply chain compromise:** A compromised dependency in your frontend bundle can silently exfiltrate tokens at runtime without triggering any security controls.

In every one of these scenarios, the attacker obtains a value that they can use from their own machine to impersonate the user. The server cannot tell the difference between the attacker and the real user -- the token is the identity.

**Even "short-lived" tokens don't fully solve this.** A JWT with a 15-minute lifetime gives an attacker a 15-minute window to perform any operation. Refresh token rotation helps, but adds complexity and still relies on the refresh token itself being a bearer credential.

### How HTTP Signatures Are Different

With HTTP Message Signatures, the client holds a **private key** that never leaves the device. For each request, the client computes a cryptographic signature over the request's method, URL, headers, and body digest. The server verifies the signature using the corresponding public key.

```
POST /api/transfer HTTP/1.1
Host: bank.example
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig1=("@method" "@path" "@authority" "content-digest")\
    ;created=1618884473;keyid="user-key-1";alg="ecdsa-p256-sha256"
Signature: sig1=:MEUCIQCBWmSoOGNsuikGbCBm...rest of signature...:

{"to": "acct-789", "amount": 500}
```

What makes this secure:

- **Nothing to steal.** The private key is never transmitted. An attacker who intercepts the request gets the signature, but the signature is only valid for that exact request at that exact moment. It cannot be replayed for a different request, a different path, a different body, or even the same request after the signature expires.
- **Non-extractable keys.** On modern platforms, the private key can live in hardware that makes it physically impossible to export: the [Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web) on Apple devices, [Android Keystore](https://developer.android.com/privacy-and-security/keystore) on Android, [HSMs](https://en.wikipedia.org/wiki/Hardware_security_module) and [PKCS#11 tokens](https://en.wikipedia.org/wiki/PKCS_11) on servers, and the [Web Crypto API](https://developer.mozilla.org/en-US/Web/API/Web_Crypto_API) in browsers (with `extractable: false`). Even if the entire device is compromised at the software level, the key cannot be read out.
- **Request-specific.** The signature covers the HTTP method, URL, headers, and body digest. An attacker who captures a signed `GET /api/balance` cannot modify it into a `POST /api/transfer`. Changing any covered component invalidates the signature.
- **Time-bound.** The `created` and optional `expires` parameters scope the signature to a narrow time window. A captured signature from yesterday is worthless today.
- **XSS-resistant.** A cross-site scripting attack cannot steal a key that JavaScript cannot access. With Web Crypto's non-extractable keys, even malicious JavaScript running in the same origin cannot read the private key material -- it can only ask the browser to sign, which limits the attacker to the signatures they can trigger during the XSS window, not persistent impersonation.

### Session Cookies vs. HTTP Signatures: A Comparison

| Property | Session cookie / JWT | HTTP Message Signature |
|---|---|---|
| **What travels in each request** | The secret itself (cookie, token) | A proof derived from the secret (signature) |
| **What an attacker needs** | The token (a copyable string) | The private key (non-extractable from hardware) |
| **Replay from another device** | Yes -- token works from anywhere | No -- attacker would need the private key |
| **XSS token theft** | JS reads cookie or localStorage | Non-extractable key cannot be read by JS |
| **Leaked in server logs** | Common (`Authorization` headers, cookies) | Signature is useless without the key |
| **Stolen via compromised proxy** | Token in cleartext after TLS termination | Signature only valid for that one request |
| **Scope of damage** | Full account access until expiry/revocation | At most, requests the attacker can trigger in real time |
| **Non-repudiation** | No -- server generated the token | Yes -- only the key holder could have signed (asymmetric) |
| **Body integrity** | Not guaranteed (token doesn't cover body) | Covered via `Content-Digest` |

### When Bearer Tokens Still Make Sense

HTTP signatures are not a universal replacement for all token-based auth. They are strongest in scenarios where:

- **The client can hold a private key** -- native apps, server-to-server, IoT devices, browsers with Web Crypto support.
- **Per-request integrity matters** -- financial APIs, infrastructure control planes, webhook delivery.
- **Token theft is a real threat** -- public-facing APIs, zero-trust architectures, regulatory environments requiring non-repudiation.

Simple session cookies may still be the right choice for low-stakes browser sessions where the primary threat model is CSRF (mitigated by `SameSite` cookies) rather than token exfiltration. But as applications move toward zero-trust networking, API-first architectures, and regulatory requirements for strong authentication, per-request signing with non-extractable keys becomes the stronger foundation.

## What This Library Provides

**httpsig** handles the complex parts -- signature base construction, structured field serialization, algorithm negotiation, and key management -- so you can add per-request signing to any HTTP client or server in a few lines of code.

### Supported Algorithms

| Algorithm | Type | Notes |
|---|---|---|
| **ecdsa-p256-sha256** | Asymmetric | Best balance of speed, security, and KMS support |
| **ed25519** | Asymmetric | Fastest, compact signatures |
| **rsa-pss-sha512** | Asymmetric | Wide legacy support |
| **hmac-sha256** | Symmetric | Shared-secret scenarios |

### Supported Languages

| Language | Package | Integrations |
|---|---|---|
| Go | `github.com/zourzouvillys/httpsig/golang` | net/http (RoundTripper + Handler middleware) |
| TypeScript | `@zourzouvillys/httpsig` | fetch, axios, undici |
| Java | `io.zrz:httpsig` | OkHttp, JDK HttpClient, Spring WebClient |
| Swift | `HTTPSig` (SPM) | URLSession, Alamofire |
| Kotlin | `io.zrz:httpsig-kotlin` | OkHttp, Ktor |

All five implementations share the same test vectors derived from RFC 9421 Appendix B, ensuring cross-language interoperability.

### Hardware Key Support

Every platform has a path to non-extractable keys:

| Platform | Key Storage | Notes |
|---|---|---|
| **Apple (Swift)** | Secure Enclave | P-256 keys created and used without ever exposing key material |
| **Android (Kotlin/Java)** | Android Keystore | Hardware-backed on devices with a secure element |
| **Server (Go/Java)** | HSM / PKCS#11 | CloudHSM, YubiHSM, or any PKCS#11 device |
| **Browser (TypeScript)** | Web Crypto API | `extractable: false` keys backed by the browser's crypto subsystem |
| **Cloud (all)** | AWS KMS, GCP Cloud KMS, Azure Key Vault | [Envelope pattern](/concepts/security#high-throughput-signing-with-kms-backed-keys) for high-throughput signing |

### Key Features

- Full RFC 9421 signature base construction and verification
- Content-Digest generation and verification (RFC 9530, SHA-256 and SHA-512)
- All standard derived components: `@method`, `@path`, `@authority`, `@query`, `@query-param`, `@status`, `@scheme`, `@target-uri`, `@request-target`
- Header field signing with `;sf`, `;bs`, `;key`, and `;req` parameters
- `KeyPair` type with auto-detection: pass any private key, the library detects the algorithm and derives the public key
- Response signing with request binding (cryptographic proof that a response was generated for a specific request)
- Verification security: algorithm consistency checks, future-dated signature rejection (`maxClockSkew`), replay protection via `maxAge` and `expires`

## Next Steps

- Pick your language and follow the **Getting Started** guide: [Go](/getting-started/go) | [TypeScript](/getting-started/typescript) | [Java](/getting-started/java) | [Swift](/getting-started/swift) | [Kotlin](/getting-started/kotlin)
- Read [How It Works](/concepts/how-it-works) for the theory behind RFC 9421
- See the [Signing Guide](/guides/signing) for end-to-end examples
- Review the [Security Architecture](/concepts/security) for threat modeling and request-response binding
