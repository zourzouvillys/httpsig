---
sidebar_position: 3
---

# Algorithms

httpsig supports 11 signature algorithms across all five language implementations.

## Algorithm Reference

| Algorithm | Type | Key Size | Signature Size | RFC Registered |
|---|---|---|---|---|
| `ecdsa-p256-sha256` | Asymmetric | 256-bit EC | 64 bytes | Yes |
| `ecdsa-p384-sha384` | Asymmetric | 384-bit EC | 96 bytes | Yes |
| `ecdsa-p521-sha512` | Asymmetric | 521-bit EC | 132 bytes | No |
| `ed25519` | Asymmetric | 256-bit | 64 bytes | Yes |
| `rsa-pss-sha512` | Asymmetric | 2048+ bit RSA | 256 bytes (2048-bit) | Yes |
| `rsa-pss-sha384` | Asymmetric | 2048+ bit RSA | 256 bytes (2048-bit) | No |
| `rsa-pss-sha256` | Asymmetric | 2048+ bit RSA | 256 bytes (2048-bit) | No |
| `rsa-v1_5-sha256` | Asymmetric | 2048+ bit RSA | 256 bytes (2048-bit) | Yes |
| `hmac-sha256` | Symmetric | 256-bit secret | 32 bytes | Yes |
| `hmac-sha384` | Symmetric | 384-bit secret | 48 bytes | No |
| `hmac-sha512` | Symmetric | 512-bit secret | 64 bytes | No |

The six "RFC Registered" algorithms are in the [IANA HTTP Message Signatures registry](https://www.iana.org/assignments/http-message-signatures/http-message-signatures.xhtml). The others are widely used and supported by other implementations (e.g., dadrus/httpsig).

## When to Use Each

### Ed25519

The best default choice for new systems. Ed25519 provides:

- Fast signing and verification
- Small keys and signatures (64 bytes)
- No configuration parameters (no hash function or padding to get wrong)
- Deterministic signatures (in most implementations; Apple CryptoKit uses randomized signing for side-channel resistance)

### ECDSA (P-256, P-384, P-521)

Use ECDSA when you need NIST-approved algorithms or need to integrate with systems that already use EC keys (TLS certificates, JWK, etc.). Signatures use raw `r||s` format per RFC 9421 (not DER).

| Curve | Signature Size | Use Case |
|---|---|---|
| **P-256** | 64 bytes | General purpose, best KMS support, widest compatibility |
| **P-384** | 96 bytes | CNSA Suite compliance, higher security margin |
| **P-521** | 132 bytes | Maximum EC security level |

**Recommendation:** P-256 unless your compliance requirements mandate a larger curve.

### RSA-PSS (SHA-256, SHA-384, SHA-512)

Use when integrating with legacy systems that require RSA, or when your keys are stored in hardware that only supports RSA. RSA-PSS (Probabilistic Signature Scheme) is the recommended RSA padding mode.

| Hash | Salt Length | Use Case |
|---|---|---|
| **SHA-512** | 64 bytes | Default RSA-PSS (RFC 9421 registered) |
| **SHA-384** | 48 bytes | Middle ground |
| **SHA-256** | 32 bytes | Smallest RSA-PSS hash |

Signatures are significantly larger than EC or Ed25519 (256 bytes for a 2048-bit key).

### RSA PKCS#1 v1.5 (`rsa-v1_5-sha256`)

Use only for interoperability with systems that cannot support RSA-PSS. PKCS#1 v1.5 is a deterministic padding scheme with known theoretical weaknesses (Bleichenbacher-style attacks), though these do not directly apply to signature verification. RFC 9421 registers this algorithm but recommends PSS where possible.

### HMAC (SHA-256, SHA-384, SHA-512)

Symmetric algorithms where both parties share the same secret key.

| Hash | MAC Size | Use Case |
|---|---|---|
| **SHA-256** | 32 bytes | Default, sufficient for most deployments |
| **SHA-384** | 48 bytes | Higher security margin |
| **SHA-512** | 64 bytes | Maximum HMAC security |

Because the same key signs and verifies, HMAC does not provide non-repudiation: any party that can verify a signature can also forge one. Use for internal service-to-service communication where key distribution is not an issue.

## Algorithm Constants

Each language exposes algorithm identifiers as constants or string literals:

### ECDSA

| Language | P-256 | P-384 | P-521 |
|---|---|---|---|
| Go | `AlgorithmECDSAP256SHA256` | `AlgorithmECDSAP384SHA384` | `AlgorithmECDSAP521SHA512` |
| TypeScript | `"ecdsa-p256-sha256"` | `"ecdsa-p384-sha384"` | `"ecdsa-p521-sha512"` |
| Java | `Algorithm.ECDSA_P256_SHA256` | `Algorithm.ECDSA_P384_SHA384` | `Algorithm.ECDSA_P521_SHA512` |
| Swift | `.ecdsaP256Sha256` | `.ecdsaP384Sha384` | `.ecdsaP521Sha512` |
| Kotlin | `Algorithm.EcdsaP256Sha256` | `Algorithm.EcdsaP384Sha384` | `Algorithm.EcdsaP521Sha512` |

### Ed25519

| Language | Constant |
|---|---|
| Go | `AlgorithmEd25519` |
| TypeScript | `"ed25519"` |
| Java | `Algorithm.ED25519` |
| Swift | `.ed25519` |
| Kotlin | `Algorithm.Ed25519` |

### RSA

| Language | PSS-SHA512 | PSS-SHA384 | PSS-SHA256 | PKCS1v1.5-SHA256 |
|---|---|---|---|---|
| Go | `AlgorithmRSAPSSSHA512` | `AlgorithmRSAPSSSHA384` | `AlgorithmRSAPSSSHA256` | `AlgorithmRSAV15SHA256` |
| TypeScript | `"rsa-pss-sha512"` | `"rsa-pss-sha384"` | `"rsa-pss-sha256"` | `"rsa-v1_5-sha256"` |
| Java | `Algorithm.RSA_PSS_SHA512` | `Algorithm.RSA_PSS_SHA384` | `Algorithm.RSA_PSS_SHA256` | `Algorithm.RSA_V1_5_SHA256` |
| Swift | `.rsaPssSha512` | `.rsaPssSha384` | `.rsaPssSha256` | `.rsaV1_5Sha256` |
| Kotlin | `Algorithm.RsaPssSha512` | `Algorithm.RsaPssSha384` | `Algorithm.RsaPssSha256` | `Algorithm.RsaV15Sha256` |

### HMAC

| Language | SHA-256 | SHA-384 | SHA-512 |
|---|---|---|---|
| Go | `AlgorithmHMACSHA256` | `AlgorithmHMACSHA384` | `AlgorithmHMACSHA512` |
| TypeScript | `"hmac-sha256"` | `"hmac-sha384"` | `"hmac-sha512"` |
| Java | `Algorithm.HMAC_SHA256` | `Algorithm.HMAC_SHA384` | `Algorithm.HMAC_SHA512` |
| Swift | `.hmacSha256` | `.hmacSha384` | `.hmacSha512` |
| Kotlin | `Algorithm.HmacSha256` | `Algorithm.HmacSha384` | `Algorithm.HmacSha512` |

## Algorithm in Signature Parameters

The `alg` parameter in the signature metadata is optional. When present, it tells the verifier which algorithm the signer used. When absent, the verifier determines the algorithm from the key.

In the httpsig test vectors, the `alg` parameter is intentionally omitted to test algorithm inference from the key. In production, including `alg` is recommended as a defense-in-depth measure.
