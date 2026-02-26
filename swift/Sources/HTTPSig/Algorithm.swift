/// Signature algorithms defined in RFC 9421 Section 3.3.
public enum Algorithm: String, Sendable, Equatable, Hashable {
    case rsaPssSha512 = "rsa-pss-sha512"
    case ecdsaP256Sha256 = "ecdsa-p256-sha256"
    case ed25519 = "ed25519"
    case hmacSha256 = "hmac-sha256"
}
