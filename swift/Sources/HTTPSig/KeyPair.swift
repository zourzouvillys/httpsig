import Foundation
import CryptoKit
@preconcurrency import Security

/// Bundles a signing and verifying key that share the same key ID and algorithm.
public struct KeyPair: Sendable {
    public let keyId: String
    public let algorithm: Algorithm
    public let signingKey: any SigningKey
    public let verifyingKey: any VerifyingKey

    /// Create a KeyPair from an Ed25519 private key. The public key is derived automatically.
    public static func ed25519(keyId: String, privateKey: Curve25519.Signing.PrivateKey) -> KeyPair {
        KeyPair(
            keyId: keyId,
            algorithm: .ed25519,
            signingKey: Ed25519SigningKey(keyId: keyId, privateKey: privateKey),
            verifyingKey: Ed25519VerifyingKey(keyId: keyId, publicKey: privateKey.publicKey)
        )
    }

    /// Create a KeyPair from an ECDSA P-256 private key. The public key is derived automatically.
    public static func ecdsaP256(keyId: String, privateKey: P256.Signing.PrivateKey) -> KeyPair {
        KeyPair(
            keyId: keyId,
            algorithm: .ecdsaP256Sha256,
            signingKey: ECDSAP256SigningKey(keyId: keyId, privateKey: privateKey),
            verifyingKey: ECDSAP256VerifyingKey(keyId: keyId, publicKey: privateKey.publicKey)
        )
    }

    /// Create a KeyPair from an RSA SecKey. The public key is extracted via `SecKeyCopyPublicKey`.
    public static func rsaPSS(keyId: String, secKey: SecKey) throws -> KeyPair {
        guard let pubKey = SecKeyCopyPublicKey(secKey) else {
            throw HttpSigError.invalidKey("cannot extract public key from RSA SecKey")
        }
        return KeyPair(
            keyId: keyId,
            algorithm: .rsaPssSha512,
            signingKey: RSAPSSSigningKey(keyId: keyId, secKey: secKey),
            verifyingKey: RSAPSSVerifyingKey(keyId: keyId, secKey: pubKey)
        )
    }

    /// Create a KeyPair for HMAC-SHA256. The same secret backs both signing and verifying.
    public static func hmacSHA256(keyId: String, secret: Data) -> KeyPair {
        let key = HMACSHA256Key(keyId: keyId, secret: secret)
        return KeyPair(
            keyId: keyId,
            algorithm: .hmacSha256,
            signingKey: key,
            verifyingKey: key
        )
    }
}
