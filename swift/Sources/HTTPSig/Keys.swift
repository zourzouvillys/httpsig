import Foundation
import CryptoKit
@preconcurrency import Security

// MARK: - Ed25519

/// Ed25519 signing key backed by CryptoKit.
public struct Ed25519SigningKey: SigningKey {
    public let keyId: String
    public let algorithm: Algorithm = .ed25519
    private let key: Curve25519.Signing.PrivateKey

    public init(keyId: String, privateKey: Curve25519.Signing.PrivateKey) {
        self.keyId = keyId
        self.key = privateKey
    }

    /// Load from a PKCS#8 DER-encoded private key.
    public init(keyId: String, pkcs8DER data: Data) throws {
        self.keyId = keyId
        // PKCS#8 wrapping for Ed25519: the raw 32 bytes are at the end of the DER
        // structure. The prefix is 16 bytes for Ed25519 PKCS#8.
        // 30 2e (SEQUENCE, 46 bytes)
        //   02 01 00 (INTEGER 0 = version)
        //   30 05 (SEQUENCE, 5 bytes)
        //     06 03 2b 65 70 (OID 1.3.101.112 = Ed25519)
        //   04 22 (OCTET STRING, 34 bytes)
        //     04 20 (OCTET STRING, 32 bytes)
        //       <32 bytes of raw key>
        guard data.count >= 18 else {
            throw HttpSigError.invalidKey("Ed25519 PKCS#8 key too short")
        }
        // Find the raw key: last 32 bytes, preceded by 04 20
        let rawKeyStart = data.count - 32
        guard rawKeyStart >= 2,
              data[rawKeyStart - 2] == 0x04,
              data[rawKeyStart - 1] == 0x20 else {
            throw HttpSigError.invalidKey("cannot extract Ed25519 raw key from PKCS#8")
        }
        let rawKey = data[rawKeyStart...]
        self.key = try Curve25519.Signing.PrivateKey(rawRepresentation: rawKey)
    }

    public func sign(_ data: Data) throws -> Data {
        try Data(key.signature(for: data))
    }
}

/// Ed25519 verifying key backed by CryptoKit.
public struct Ed25519VerifyingKey: VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .ed25519
    private let key: Curve25519.Signing.PublicKey

    public init(keyId: String, publicKey: Curve25519.Signing.PublicKey) {
        self.keyId = keyId
        self.key = publicKey
    }

    /// Load from an SPKI DER-encoded public key.
    public init(keyId: String, spkiDER data: Data) throws {
        self.keyId = keyId
        // SPKI for Ed25519: 12-byte prefix + 32 bytes raw key
        // 30 2a (SEQUENCE, 42 bytes)
        //   30 05 (SEQUENCE, 5 bytes)
        //     06 03 2b 65 70 (OID 1.3.101.112)
        //   03 21 00 (BIT STRING, 33 bytes, 0 unused bits)
        //     <32 bytes raw key>
        guard data.count >= 14 else {
            throw HttpSigError.invalidKey("Ed25519 SPKI key too short")
        }
        let rawKey = data[(data.count - 32)...]
        self.key = try Curve25519.Signing.PublicKey(rawRepresentation: rawKey)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        key.isValidSignature(signature, for: data)
    }
}

// MARK: - ECDSA P-256

/// ECDSA P-256 signing key backed by CryptoKit.
public struct ECDSAP256SigningKey: SigningKey {
    public let keyId: String
    public let algorithm: Algorithm = .ecdsaP256Sha256
    private let key: P256.Signing.PrivateKey

    public init(keyId: String, privateKey: P256.Signing.PrivateKey) {
        self.keyId = keyId
        self.key = privateKey
    }

    /// Load from a SEC1 (OpenSSL EC) DER-encoded private key.
    public init(keyId: String, derRepresentation data: Data) throws {
        self.keyId = keyId
        self.key = try P256.Signing.PrivateKey(derRepresentation: data)
    }

    public func sign(_ data: Data) throws -> Data {
        // CryptoKit P256 produces DER-encoded signatures by default.
        // RFC 9421 requires raw r||s format (64 bytes).
        let sig = try key.signature(for: SHA256.hash(data: data))
        return sig.rawRepresentation
    }
}

/// ECDSA P-256 verifying key backed by CryptoKit.
public struct ECDSAP256VerifyingKey: VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .ecdsaP256Sha256
    private let key: P256.Signing.PublicKey

    public init(keyId: String, publicKey: P256.Signing.PublicKey) {
        self.keyId = keyId
        self.key = publicKey
    }

    /// Load from an SPKI DER-encoded public key.
    public init(keyId: String, derRepresentation data: Data) throws {
        self.keyId = keyId
        self.key = try P256.Signing.PublicKey(derRepresentation: data)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        guard signature.count == 64 else { return false }
        let ecSig = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return key.isValidSignature(ecSig, for: SHA256.hash(data: data))
    }
}

// MARK: - ECDSA P-384

/// ECDSA P-384 signing key backed by CryptoKit.
public struct ECDSAP384SigningKey: SigningKey {
    public let keyId: String
    public let algorithm: Algorithm = .ecdsaP384Sha384
    private let key: P384.Signing.PrivateKey

    public init(keyId: String, privateKey: P384.Signing.PrivateKey) {
        self.keyId = keyId
        self.key = privateKey
    }

    /// Load from a SEC1 (OpenSSL EC) DER-encoded private key.
    public init(keyId: String, derRepresentation data: Data) throws {
        self.keyId = keyId
        self.key = try P384.Signing.PrivateKey(derRepresentation: data)
    }

    public func sign(_ data: Data) throws -> Data {
        // RFC 9421 requires raw r||s format (96 bytes for P-384).
        let sig = try key.signature(for: SHA384.hash(data: data))
        return sig.rawRepresentation
    }
}

/// ECDSA P-384 verifying key backed by CryptoKit.
public struct ECDSAP384VerifyingKey: VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .ecdsaP384Sha384
    private let key: P384.Signing.PublicKey

    public init(keyId: String, publicKey: P384.Signing.PublicKey) {
        self.keyId = keyId
        self.key = publicKey
    }

    /// Load from an SPKI DER-encoded public key.
    public init(keyId: String, derRepresentation data: Data) throws {
        self.keyId = keyId
        self.key = try P384.Signing.PublicKey(derRepresentation: data)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        guard signature.count == 96 else { return false }
        let ecSig = try P384.Signing.ECDSASignature(rawRepresentation: signature)
        return key.isValidSignature(ecSig, for: SHA384.hash(data: data))
    }
}

// MARK: - ECDSA P-521

/// ECDSA P-521 signing key backed by CryptoKit.
public struct ECDSAP521SigningKey: SigningKey {
    public let keyId: String
    public let algorithm: Algorithm = .ecdsaP521Sha512
    private let key: P521.Signing.PrivateKey

    public init(keyId: String, privateKey: P521.Signing.PrivateKey) {
        self.keyId = keyId
        self.key = privateKey
    }

    /// Load from a SEC1 (OpenSSL EC) DER-encoded private key.
    public init(keyId: String, derRepresentation data: Data) throws {
        self.keyId = keyId
        self.key = try P521.Signing.PrivateKey(derRepresentation: data)
    }

    public func sign(_ data: Data) throws -> Data {
        // RFC 9421 requires raw r||s format (132 bytes for P-521).
        let sig = try key.signature(for: SHA512.hash(data: data))
        return sig.rawRepresentation
    }
}

/// ECDSA P-521 verifying key backed by CryptoKit.
public struct ECDSAP521VerifyingKey: VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .ecdsaP521Sha512
    private let key: P521.Signing.PublicKey

    public init(keyId: String, publicKey: P521.Signing.PublicKey) {
        self.keyId = keyId
        self.key = publicKey
    }

    /// Load from an SPKI DER-encoded public key.
    public init(keyId: String, derRepresentation data: Data) throws {
        self.keyId = keyId
        self.key = try P521.Signing.PublicKey(derRepresentation: data)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        guard signature.count == 132 else { return false }
        let ecSig = try P521.Signing.ECDSASignature(rawRepresentation: signature)
        return key.isValidSignature(ecSig, for: SHA512.hash(data: data))
    }
}

// MARK: - RSA Helpers

/// Shared utilities for RSA key types backed by the Security framework.
enum RSAKeyUtils {
    /// Parse PKCS#8 to extract the inner PKCS#1 RSAPrivateKey.
    /// PKCS#8 wraps it in: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { pkcs1 } }
    static func extractPKCS1FromPKCS8(_ data: Data) throws -> Data {
        // Simple ASN.1 DER parser, just enough to unwrap PKCS#8.
        var offset = 0
        let bytes = Array(data)

        func readTag() throws -> UInt8 {
            guard offset < bytes.count else {
                throw HttpSigError.invalidKey("unexpected end of ASN.1 data")
            }
            let tag = bytes[offset]; offset += 1
            return tag
        }

        func readLength() throws -> Int {
            guard offset < bytes.count else {
                throw HttpSigError.invalidKey("unexpected end of ASN.1 data")
            }
            let first = bytes[offset]; offset += 1
            if first < 0x80 { return Int(first) }
            let numBytes = Int(first & 0x7f)
            guard offset + numBytes <= bytes.count else {
                throw HttpSigError.invalidKey("unexpected end of ASN.1 length")
            }
            var length = 0
            for i in 0..<numBytes {
                length = (length << 8) | Int(bytes[offset + i])
            }
            offset += numBytes
            return length
        }

        // Outer SEQUENCE
        let outerTag = try readTag()
        guard outerTag == 0x30 else {
            throw HttpSigError.invalidKey("expected SEQUENCE, got \(outerTag)")
        }
        _ = try readLength()

        // Version INTEGER
        let verTag = try readTag()
        guard verTag == 0x02 else {
            throw HttpSigError.invalidKey("expected INTEGER for version, got \(verTag)")
        }
        let verLen = try readLength()
        offset += verLen // skip version bytes

        // AlgorithmIdentifier SEQUENCE
        let algTag = try readTag()
        guard algTag == 0x30 else {
            throw HttpSigError.invalidKey("expected SEQUENCE for AlgorithmIdentifier, got \(algTag)")
        }
        let algLen = try readLength()
        offset += algLen // skip algorithm identifier

        // OCTET STRING containing the PKCS#1 key
        let octetTag = try readTag()
        guard octetTag == 0x04 else {
            throw HttpSigError.invalidKey("expected OCTET STRING, got \(octetTag)")
        }
        let octetLen = try readLength()
        guard offset + octetLen <= bytes.count else {
            throw HttpSigError.invalidKey("OCTET STRING extends past data")
        }
        return Data(bytes[offset..<(offset + octetLen)])
    }

    /// Import an RSA private key from PKCS#8 DER data via the Security framework.
    static func importPrivateKey(pkcs8DER data: Data) throws -> SecKey {
        let pkcs1 = try extractPKCS1FromPKCS8(data)
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(pkcs1 as CFData, attrs as CFDictionary, &error) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw HttpSigError.invalidKey("RSA private key import failed: \(desc)")
        }
        return key
    }

    /// Import an RSA public key from SPKI DER data via the Security framework.
    static func importPublicKey(spkiDER data: Data) throws -> SecKey {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw HttpSigError.invalidKey("RSA public key import failed: \(desc)")
        }
        return key
    }
}

// MARK: - RSA-PSS-SHA512

/// RSA-PSS-SHA512 signing key backed by the Security framework.
public struct RSAPSSSigningKey: SigningKey {
    public let keyId: String
    public let algorithm: Algorithm = .rsaPssSha512
    private let secKey: SecKey

    public init(keyId: String, secKey: SecKey) {
        self.keyId = keyId
        self.secKey = secKey
    }

    /// Load from a PKCS#8 DER-encoded RSA private key.
    public init(keyId: String, pkcs8DER data: Data) throws {
        self.keyId = keyId
        self.secKey = try RSAKeyUtils.importPrivateKey(pkcs8DER: data)
    }

    public func sign(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            secKey,
            .rsaSignatureMessagePSSSHA512,
            data as CFData,
            &error
        ) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw HttpSigError.invalidKey("RSA-PSS-SHA512 sign failed: \(desc)")
        }
        return sig as Data
    }
}

/// RSA-PSS-SHA512 verifying key backed by the Security framework.
public struct RSAPSSVerifyingKey: VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .rsaPssSha512
    private let secKey: SecKey

    public init(keyId: String, secKey: SecKey) {
        self.keyId = keyId
        self.secKey = secKey
    }

    /// Load from an SPKI DER-encoded RSA public key.
    public init(keyId: String, spkiDER data: Data) throws {
        self.keyId = keyId
        self.secKey = try RSAKeyUtils.importPublicKey(spkiDER: data)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            secKey,
            .rsaSignatureMessagePSSSHA512,
            data as CFData,
            signature as CFData,
            &error
        )
        return result
    }
}

// MARK: - RSA-PSS-SHA384

/// RSA-PSS-SHA384 signing key backed by the Security framework.
public struct RSAPSSSHA384SigningKey: SigningKey {
    public let keyId: String
    public let algorithm: Algorithm = .rsaPssSha384
    private let secKey: SecKey

    public init(keyId: String, secKey: SecKey) {
        self.keyId = keyId
        self.secKey = secKey
    }

    /// Load from a PKCS#8 DER-encoded RSA private key.
    public init(keyId: String, pkcs8DER data: Data) throws {
        self.keyId = keyId
        self.secKey = try RSAKeyUtils.importPrivateKey(pkcs8DER: data)
    }

    public func sign(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            secKey,
            .rsaSignatureMessagePSSSHA384,
            data as CFData,
            &error
        ) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw HttpSigError.invalidKey("RSA-PSS-SHA384 sign failed: \(desc)")
        }
        return sig as Data
    }
}

/// RSA-PSS-SHA384 verifying key backed by the Security framework.
public struct RSAPSSSHA384VerifyingKey: VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .rsaPssSha384
    private let secKey: SecKey

    public init(keyId: String, secKey: SecKey) {
        self.keyId = keyId
        self.secKey = secKey
    }

    /// Load from an SPKI DER-encoded RSA public key.
    public init(keyId: String, spkiDER data: Data) throws {
        self.keyId = keyId
        self.secKey = try RSAKeyUtils.importPublicKey(spkiDER: data)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            secKey,
            .rsaSignatureMessagePSSSHA384,
            data as CFData,
            signature as CFData,
            &error
        )
        return result
    }
}

// MARK: - RSA-PSS-SHA256

/// RSA-PSS-SHA256 signing key backed by the Security framework.
public struct RSAPSSSHA256SigningKey: SigningKey {
    public let keyId: String
    public let algorithm: Algorithm = .rsaPssSha256
    private let secKey: SecKey

    public init(keyId: String, secKey: SecKey) {
        self.keyId = keyId
        self.secKey = secKey
    }

    /// Load from a PKCS#8 DER-encoded RSA private key.
    public init(keyId: String, pkcs8DER data: Data) throws {
        self.keyId = keyId
        self.secKey = try RSAKeyUtils.importPrivateKey(pkcs8DER: data)
    }

    public func sign(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            secKey,
            .rsaSignatureMessagePSSSHA256,
            data as CFData,
            &error
        ) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw HttpSigError.invalidKey("RSA-PSS-SHA256 sign failed: \(desc)")
        }
        return sig as Data
    }
}

/// RSA-PSS-SHA256 verifying key backed by the Security framework.
public struct RSAPSSSHA256VerifyingKey: VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .rsaPssSha256
    private let secKey: SecKey

    public init(keyId: String, secKey: SecKey) {
        self.keyId = keyId
        self.secKey = secKey
    }

    /// Load from an SPKI DER-encoded RSA public key.
    public init(keyId: String, spkiDER data: Data) throws {
        self.keyId = keyId
        self.secKey = try RSAKeyUtils.importPublicKey(spkiDER: data)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            secKey,
            .rsaSignatureMessagePSSSHA256,
            data as CFData,
            signature as CFData,
            &error
        )
        return result
    }
}

// MARK: - RSA PKCS1v1.5 SHA-256

/// RSA PKCS1v1.5 SHA-256 signing key backed by the Security framework.
public struct RSAV1_5SHA256SigningKey: SigningKey {
    public let keyId: String
    public let algorithm: Algorithm = .rsaV1_5Sha256
    private let secKey: SecKey

    public init(keyId: String, secKey: SecKey) {
        self.keyId = keyId
        self.secKey = secKey
    }

    /// Load from a PKCS#8 DER-encoded RSA private key.
    public init(keyId: String, pkcs8DER data: Data) throws {
        self.keyId = keyId
        self.secKey = try RSAKeyUtils.importPrivateKey(pkcs8DER: data)
    }

    public func sign(_ data: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            secKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            data as CFData,
            &error
        ) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw HttpSigError.invalidKey("RSA-v1_5-SHA256 sign failed: \(desc)")
        }
        return sig as Data
    }
}

/// RSA PKCS1v1.5 SHA-256 verifying key backed by the Security framework.
public struct RSAV1_5SHA256VerifyingKey: VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .rsaV1_5Sha256
    private let secKey: SecKey

    public init(keyId: String, secKey: SecKey) {
        self.keyId = keyId
        self.secKey = secKey
    }

    /// Load from an SPKI DER-encoded RSA public key.
    public init(keyId: String, spkiDER data: Data) throws {
        self.keyId = keyId
        self.secKey = try RSAKeyUtils.importPublicKey(spkiDER: data)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(
            secKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            data as CFData,
            signature as CFData,
            &error
        )
        return result
    }
}

// MARK: - HMAC-SHA256

/// HMAC-SHA256 symmetric key. Implements both SigningKey and VerifyingKey.
public struct HMACSHA256Key: SigningKey, VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .hmacSha256
    private let secret: SymmetricKey

    public init(keyId: String, secret: Data) {
        self.keyId = keyId
        self.secret = SymmetricKey(data: secret)
    }

    public func sign(_ data: Data) throws -> Data {
        let mac = CryptoKit.HMAC<SHA256>.authenticationCode(for: data, using: secret)
        return Data(mac)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        CryptoKit.HMAC<SHA256>.isValidAuthenticationCode(signature, authenticating: data, using: secret)
    }
}

// MARK: - HMAC-SHA384

/// HMAC-SHA384 symmetric key. Implements both SigningKey and VerifyingKey.
public struct HMACSHA384Key: SigningKey, VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .hmacSha384
    private let secret: SymmetricKey

    public init(keyId: String, secret: Data) {
        self.keyId = keyId
        self.secret = SymmetricKey(data: secret)
    }

    public func sign(_ data: Data) throws -> Data {
        let mac = CryptoKit.HMAC<SHA384>.authenticationCode(for: data, using: secret)
        return Data(mac)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        CryptoKit.HMAC<SHA384>.isValidAuthenticationCode(signature, authenticating: data, using: secret)
    }
}

// MARK: - HMAC-SHA512

/// HMAC-SHA512 symmetric key. Implements both SigningKey and VerifyingKey.
public struct HMACSHA512Key: SigningKey, VerifyingKey {
    public let keyId: String
    public let algorithm: Algorithm = .hmacSha512
    private let secret: SymmetricKey

    public init(keyId: String, secret: Data) {
        self.keyId = keyId
        self.secret = SymmetricKey(data: secret)
    }

    public func sign(_ data: Data) throws -> Data {
        let mac = CryptoKit.HMAC<SHA512>.authenticationCode(for: data, using: secret)
        return Data(mac)
    }

    public func verify(_ data: Data, signature: Data) throws -> Bool {
        CryptoKit.HMAC<SHA512>.isValidAuthenticationCode(signature, authenticating: data, using: secret)
    }
}

// MARK: - Secure Enclave

/// ECDSA P-256 signing key backed by the Secure Enclave.
///
/// The Secure Enclave provides hardware-backed key storage where the private key
/// never leaves the secure hardware. The algorithm is always `.ecdsaP256Sha256`.
///
/// Only available on devices with a Secure Enclave (most Apple devices since 2013).
@available(macOS 10.15, iOS 13.0, tvOS 13.0, watchOS 6.0, *)
public struct SecureEnclaveSigningKey: SigningKey, Sendable {
    public let keyId: String
    public let algorithm: Algorithm = .ecdsaP256Sha256
    private let key: SecureEnclave.P256.Signing.PrivateKey

    /// The corresponding verifying key. The public key is always extractable from the Secure Enclave.
    public var verifyingKey: ECDSAP256VerifyingKey {
        ECDSAP256VerifyingKey(keyId: keyId, publicKey: key.publicKey)
    }

    /// Create a new P-256 key in the Secure Enclave.
    public init(keyId: String) throws {
        self.keyId = keyId
        self.key = try SecureEnclave.P256.Signing.PrivateKey()
    }

    /// Wrap an existing Secure Enclave P-256 signing key.
    public init(keyId: String, key: SecureEnclave.P256.Signing.PrivateKey) {
        self.keyId = keyId
        self.key = key
    }

    public func sign(_ data: Data) throws -> Data {
        let sig = try key.signature(for: SHA256.hash(data: data))
        return sig.rawRepresentation
    }
}

// MARK: - PEM Helpers

public enum PEMUtils {
    /// Decode a PEM file to raw DER data.
    public static func decodePEM(_ pem: String) throws -> Data {
        let lines = pem.components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") && !$0.isEmpty }
        let b64 = lines.joined()
        guard let data = Data(base64Encoded: b64) else {
            throw HttpSigError.invalidKey("invalid base64 in PEM")
        }
        return data
    }
}
