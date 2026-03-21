/// Signature algorithms defined in RFC 9421 Section 3.3.
public enum Algorithm: String, Sendable, Equatable, Hashable {
    case rsaPssSha512 = "rsa-pss-sha512"
    case rsaPssSha384 = "rsa-pss-sha384"
    case rsaPssSha256 = "rsa-pss-sha256"
    case rsaV1_5Sha256 = "rsa-v1_5-sha256"
    case ecdsaP256Sha256 = "ecdsa-p256-sha256"
    case ecdsaP384Sha384 = "ecdsa-p384-sha384"
    case ecdsaP521Sha512 = "ecdsa-p521-sha512"
    case ed25519 = "ed25519"
    case hmacSha256 = "hmac-sha256"
    case hmacSha384 = "hmac-sha384"
    case hmacSha512 = "hmac-sha512"
}
