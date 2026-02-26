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

Instead, please email security reports to: **security@zourzouvillys.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Which language implementation(s) are affected
- Potential impact

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Considerations

This library implements RFC 9421 (HTTP Message Signatures). When using it:

- Keep signing keys secure. Use platform-specific key storage (Secure Enclave, Android Keystore, HSM) when possible.
- Always verify the `created` and `expires` parameters to prevent replay attacks.
- Include sufficient covered components to prevent message tampering.
- Use `Content-Digest` (RFC 9530) to protect message bodies.
- Validate the `keyid` and `algorithm` against an allowlist during verification.
