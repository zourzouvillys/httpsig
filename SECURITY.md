# Security Policy

## Supported Versions

| Language | Version | Supported |
|---|---|---|
| Go | latest | Yes |
| TypeScript | latest | Yes |
| Java | latest | Yes |
| Swift | latest | Yes |
| Kotlin | latest | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use [GitHub Security Advisories](https://github.com/zourzouvillys/httpsig/security/advisories/new) to report vulnerabilities privately. This ensures the report is only visible to maintainers until a fix is available.

Alternatively, email security reports to: **security@zourzouvillys.com**

### What to include

- Description of the vulnerability
- Steps to reproduce
- Which language implementation(s) are affected
- Potential impact
- Suggested fix (if you have one)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Triage and initial assessment**: within 5 business days
- **Fix for critical issues**: within 7 days
- **Fix for non-critical issues**: within 30 days

### Disclosure policy

We follow coordinated disclosure. Once a fix is released, we will:

1. Publish a GitHub Security Advisory with full details
2. Credit the reporter (unless they prefer anonymity)
3. Release patched versions for all affected language implementations

## Security Considerations

This library implements RFC 9421 (HTTP Message Signatures). When using it:

- **Protect signing keys.** Use platform-specific key storage (Secure Enclave, Android Keystore, HSM, Web Crypto with non-extractable keys) when possible.
- **Validate timestamps.** Always check `created` and `expires` parameters to prevent replay attacks. Use `maxAge` in verification options.
- **Cover sufficient components.** Include `@method`, `@authority`, `@path`, and security-relevant headers in your signed components.
- **Protect message bodies.** Use `Content-Digest` (RFC 9530) and include it in your signed components to prevent body tampering.
- **Validate `keyid` and `algorithm`.** Check these against an allowlist during verification to prevent algorithm confusion attacks.
- **Use strong algorithms.** Prefer Ed25519 or ECDSA P-256 for asymmetric signatures. Use RSA-PSS only when required for compatibility.
