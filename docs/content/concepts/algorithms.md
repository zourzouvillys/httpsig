---
sidebar_position: 3
---

# Algorithms

RFC 9421 defines four signature algorithms. All httpsig implementations support all four.

## Algorithm Reference

| Algorithm            | Type       | Key Size       | Signature Size | Use Case                          |
|----------------------|------------|----------------|----------------|-----------------------------------|
| `rsa-pss-sha512`     | Asymmetric | 2048+ bit RSA  | 256 bytes (2048-bit) | Legacy systems, wide compatibility |
| `ecdsa-p256-sha256`  | Asymmetric | 256-bit EC     | 64 bytes       | General purpose, compact signatures |
| `ed25519`            | Asymmetric | 256-bit        | 64 bytes       | Modern systems, best performance  |
| `hmac-sha256`        | Symmetric  | 256-bit secret | 32 bytes       | Internal services, shared secrets |

## When to Use Each

### Ed25519

The best default choice for new systems. Ed25519 provides:

- Fast signing and verification
- Small keys and signatures (64 bytes)
- No configuration parameters (no hash function or padding to get wrong)
- Deterministic signatures (in most implementations; Apple CryptoKit uses randomized signing for side-channel resistance)

### ECDSA P-256

A good choice when you need NIST-approved algorithms or need to integrate with systems that already use P-256 keys (TLS certificates, JWK, etc.). Signatures are 64 bytes (raw `r||s` format per RFC 9421).

### RSA-PSS-SHA512

Use when integrating with legacy systems that require RSA, or when your keys are stored in hardware that only supports RSA. RSA-PSS (Probabilistic Signature Scheme) is the only RSA variant allowed by RFC 9421. PKCS#1 v1.5 is not supported.

Signatures are significantly larger than EC or Ed25519 (256 bytes for a 2048-bit key).

### HMAC-SHA256

The only symmetric algorithm. Both parties share the same secret key. Use for:

- Internal service-to-service communication where key distribution is not an issue
- Simpler deployments where you do not need non-repudiation

Because the same key signs and verifies, HMAC does not provide non-repudiation: any party that can verify a signature can also forge one.

## Algorithm Constants

Each language exposes algorithm identifiers as constants:

| Language   | Ed25519                        | ECDSA P-256                        | RSA-PSS                          | HMAC                             |
|------------|--------------------------------|------------------------------------|----------------------------------|----------------------------------|
| Go         | `AlgorithmEd25519`             | `AlgorithmECDSAP256SHA256`         | `AlgorithmRSAPSSSHA512`          | `AlgorithmHMACSHA256`            |
| TypeScript | `"ed25519"`                    | `"ecdsa-p256-sha256"`              | `"rsa-pss-sha512"`               | `"hmac-sha256"`                  |
| Java       | `Algorithm.ED25519`            | `Algorithm.ECDSA_P256_SHA256`      | `Algorithm.RSA_PSS_SHA512`       | `Algorithm.HMAC_SHA256`          |
| Swift      | `.ed25519`                     | `.ecdsaP256Sha256`                 | `.rsaPssSha512`                  | `.hmacSha256`                    |
| Kotlin     | `Algorithm.Ed25519`            | `Algorithm.EcdsaP256Sha256`        | `Algorithm.RsaPssSha512`         | `Algorithm.HmacSha256`           |

## Algorithm in Signature Parameters

The `alg` parameter in the signature metadata is optional. When present, it tells the verifier which algorithm the signer used. When absent, the verifier determines the algorithm from the key.

In the httpsig test vectors, the `alg` parameter is intentionally omitted to test algorithm inference from the key. In production, including `alg` is recommended as a defense-in-depth measure.
