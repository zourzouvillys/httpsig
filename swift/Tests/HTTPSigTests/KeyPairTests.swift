import Foundation
import Testing
import CryptoKit
@preconcurrency import Security
@testable import HTTPSig

@Suite("KeyPair")
struct KeyPairTests {

    @Test("Ed25519 KeyPair sign/verify round-trip")
    func ed25519RoundTrip() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let kp = KeyPair.ed25519(keyId: "ed-test", privateKey: privateKey)

        #expect(kp.keyId == "ed-test")
        #expect(kp.algorithm == .ed25519)

        let data = Data("test data".utf8)
        let sig = try kp.signingKey.sign(data)
        let valid = try kp.verifyingKey.verify(data, signature: sig)
        #expect(valid)

        let tampered = Data("test datA".utf8)
        let invalid = try kp.verifyingKey.verify(tampered, signature: sig)
        #expect(!invalid)
    }

    @Test("ECDSA P-256 KeyPair sign/verify round-trip")
    func ecdsaP256RoundTrip() throws {
        let privateKey = P256.Signing.PrivateKey()
        let kp = KeyPair.ecdsaP256(keyId: "ec-test", privateKey: privateKey)

        #expect(kp.keyId == "ec-test")
        #expect(kp.algorithm == .ecdsaP256Sha256)

        let data = Data("test data".utf8)
        let sig = try kp.signingKey.sign(data)
        #expect(sig.count == 64) // raw r||s
        let valid = try kp.verifyingKey.verify(data, signature: sig)
        #expect(valid)

        let tampered = Data("test datA".utf8)
        let invalid = try kp.verifyingKey.verify(tampered, signature: sig)
        #expect(!invalid)
    }

    @Test("RSA-PSS KeyPair sign/verify round-trip")
    func rsaPSSRoundTrip() throws {
        let params: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(params as CFDictionary, &error) else {
            throw HttpSigError.invalidKey("RSA key gen failed: \(error!.takeRetainedValue())")
        }

        let kp = try KeyPair.rsaPSS(keyId: "rsa-test", secKey: secKey)
        #expect(kp.keyId == "rsa-test")
        #expect(kp.algorithm == .rsaPssSha512)

        let data = Data("test data".utf8)
        let sig = try kp.signingKey.sign(data)
        let valid = try kp.verifyingKey.verify(data, signature: sig)
        #expect(valid)

        var tampered = sig
        tampered[0] ^= 0xFF
        let invalid = try kp.verifyingKey.verify(data, signature: tampered)
        #expect(!invalid)
    }

    @Test("HMAC KeyPair sign/verify round-trip")
    func hmacRoundTrip() throws {
        let secret = Data("super-secret-key-at-least-32-bytes!!".utf8)
        let kp = KeyPair.hmacSHA256(keyId: "hmac-test", secret: secret)

        #expect(kp.keyId == "hmac-test")
        #expect(kp.algorithm == .hmacSha256)

        let data = Data("test data".utf8)
        let sig = try kp.signingKey.sign(data)
        let valid = try kp.verifyingKey.verify(data, signature: sig)
        #expect(valid)

        let invalid = try kp.verifyingKey.verify(Data("wrong".utf8), signature: sig)
        #expect(!invalid)
    }

    @Test("Secure Enclave signing key (skipped without hardware)")
    func secureEnclaveWhenAvailable() throws {
        guard SecureEnclave.isAvailable else {
            return // CI machines and older Macs don't have a Secure Enclave
        }

        let seKey = try SecureEnclaveSigningKey(keyId: "se-test")
        #expect(seKey.keyId == "se-test")
        #expect(seKey.algorithm == .ecdsaP256Sha256)

        let vk = seKey.verifyingKey
        #expect(vk.keyId == "se-test")

        let data = Data("secure enclave test".utf8)
        let sig = try seKey.sign(data)
        let valid = try vk.verify(data, signature: sig)
        #expect(valid)
    }

    @Test("KeyPair key ID consistency")
    func keyIdConsistency() throws {
        let kp = KeyPair.ed25519(keyId: "consistent", privateKey: Curve25519.Signing.PrivateKey())
        #expect(kp.keyId == kp.signingKey.keyId)
        #expect(kp.keyId == kp.verifyingKey.keyId)
    }

    @Test("KeyPair algorithm consistency")
    func algorithmConsistency() throws {
        let kp = KeyPair.ecdsaP256(keyId: "alg-check", privateKey: P256.Signing.PrivateKey())
        #expect(kp.algorithm == kp.signingKey.algorithm)
        #expect(kp.algorithm == kp.verifyingKey.algorithm)
    }
}
