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

    /// Create a KeyPair from an ECDSA P-384 private key. The public key is derived automatically.
    public static func ecdsaP384(keyId: String, privateKey: P384.Signing.PrivateKey) -> KeyPair {
        KeyPair(
            keyId: keyId,
            algorithm: .ecdsaP384Sha384,
            signingKey: ECDSAP384SigningKey(keyId: keyId, privateKey: privateKey),
            verifyingKey: ECDSAP384VerifyingKey(keyId: keyId, publicKey: privateKey.publicKey)
        )
    }

    /// Create a KeyPair from an ECDSA P-521 private key. The public key is derived automatically.
    public static func ecdsaP521(keyId: String, privateKey: P521.Signing.PrivateKey) -> KeyPair {
        KeyPair(
            keyId: keyId,
            algorithm: .ecdsaP521Sha512,
            signingKey: ECDSAP521SigningKey(keyId: keyId, privateKey: privateKey),
            verifyingKey: ECDSAP521VerifyingKey(keyId: keyId, publicKey: privateKey.publicKey)
        )
    }

    /// Create a KeyPair from an RSA SecKey for RSA-PSS-SHA512. The public key is extracted via `SecKeyCopyPublicKey`.
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

    /// Create a KeyPair from an RSA SecKey for RSA-PSS-SHA384. The public key is extracted via `SecKeyCopyPublicKey`.
    public static func rsaPSSSHA384(keyId: String, secKey: SecKey) throws -> KeyPair {
        guard let pubKey = SecKeyCopyPublicKey(secKey) else {
            throw HttpSigError.invalidKey("cannot extract public key from RSA SecKey")
        }
        return KeyPair(
            keyId: keyId,
            algorithm: .rsaPssSha384,
            signingKey: RSAPSSSHA384SigningKey(keyId: keyId, secKey: secKey),
            verifyingKey: RSAPSSSHA384VerifyingKey(keyId: keyId, secKey: pubKey)
        )
    }

    /// Create a KeyPair from an RSA SecKey for RSA-PSS-SHA256. The public key is extracted via `SecKeyCopyPublicKey`.
    public static func rsaPSSSHA256(keyId: String, secKey: SecKey) throws -> KeyPair {
        guard let pubKey = SecKeyCopyPublicKey(secKey) else {
            throw HttpSigError.invalidKey("cannot extract public key from RSA SecKey")
        }
        return KeyPair(
            keyId: keyId,
            algorithm: .rsaPssSha256,
            signingKey: RSAPSSSHA256SigningKey(keyId: keyId, secKey: secKey),
            verifyingKey: RSAPSSSHA256VerifyingKey(keyId: keyId, secKey: pubKey)
        )
    }

    /// Create a KeyPair from an RSA SecKey for RSA PKCS1v1.5 SHA-256. The public key is extracted via `SecKeyCopyPublicKey`.
    public static func rsaV1_5SHA256(keyId: String, secKey: SecKey) throws -> KeyPair {
        guard let pubKey = SecKeyCopyPublicKey(secKey) else {
            throw HttpSigError.invalidKey("cannot extract public key from RSA SecKey")
        }
        return KeyPair(
            keyId: keyId,
            algorithm: .rsaV1_5Sha256,
            signingKey: RSAV1_5SHA256SigningKey(keyId: keyId, secKey: secKey),
            verifyingKey: RSAV1_5SHA256VerifyingKey(keyId: keyId, secKey: pubKey)
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

    /// Create a KeyPair for HMAC-SHA384. The same secret backs both signing and verifying.
    public static func hmacSHA384(keyId: String, secret: Data) -> KeyPair {
        let key = HMACSHA384Key(keyId: keyId, secret: secret)
        return KeyPair(
            keyId: keyId,
            algorithm: .hmacSha384,
            signingKey: key,
            verifyingKey: key
        )
    }

    /// Create a KeyPair for HMAC-SHA512. The same secret backs both signing and verifying.
    public static func hmacSHA512(keyId: String, secret: Data) -> KeyPair {
        let key = HMACSHA512Key(keyId: keyId, secret: secret)
        return KeyPair(
            keyId: keyId,
            algorithm: .hmacSha512,
            signingKey: key,
            verifyingKey: key
        )
    }
}
