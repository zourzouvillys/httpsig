import Foundation
import Testing
import CryptoKit
@preconcurrency import Security
@testable import HTTPSig

@Suite("Crypto Operations")
struct CryptoTests {

    @Test("Ed25519 sign and verify round-trip")
    func ed25519Roundtrip() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let signer = Ed25519SigningKey(keyId: "test", privateKey: privateKey)
        let verifier = Ed25519VerifyingKey(keyId: "test", publicKey: privateKey.publicKey)

        let data = Data("hello world".utf8)
        let sig = try signer.sign(data)
        let valid = try verifier.verify(data, signature: sig)
        #expect(valid)

        // Tampered data should fail
        let tampered = Data("hello worlD".utf8)
        let invalid = try verifier.verify(tampered, signature: sig)
        #expect(!invalid)
    }

    @Test("ECDSA P-256 sign and verify round-trip")
    func ecdsaP256Roundtrip() throws {
        let privateKey = P256.Signing.PrivateKey()
        let signer = ECDSAP256SigningKey(keyId: "test", privateKey: privateKey)
        let verifier = ECDSAP256VerifyingKey(keyId: "test", publicKey: privateKey.publicKey)

        let data = Data("hello world".utf8)
        let sig = try signer.sign(data)
        #expect(sig.count == 64) // raw r||s format

        let valid = try verifier.verify(data, signature: sig)
        #expect(valid)
    }

    @Test("HMAC-SHA256 sign and verify round-trip")
    func hmacRoundtrip() throws {
        let secret = Data("super-secret-key-at-least-32-bytes-long!".utf8)
        let key = HMACSHA256Key(keyId: "test", secret: secret)

        let data = Data("hello world".utf8)
        let sig = try key.sign(data)
        let valid = try key.verify(data, signature: sig)
        #expect(valid)

        // Wrong data
        let invalid = try key.verify(Data("wrong".utf8), signature: sig)
        #expect(!invalid)
    }

    @Test("HMAC-SHA256 deterministic signature")
    func hmacDeterministic() throws {
        // From test vector B.2.5
        let secretB64 = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
        let secret = Data(base64Encoded: secretB64)!
        let key = HMACSHA256Key(keyId: "test-shared-secret", secret: secret)

        let baseStr = [
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT",
            "\"@authority\": example.com",
            "\"content-type\": application/json",
            "\"@signature-params\": (\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"",
        ].joined(separator: "\n")

        let sig = try key.sign(Data(baseStr.utf8))
        let b64Sig = sig.base64EncodedString()
        #expect(b64Sig == "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=")
    }

    @Test("Ed25519 sign from PEM produces verifiable signature")
    func ed25519SignFromPEM() throws {
        // CryptoKit's Ed25519 may use randomized signing for side-channel protection,
        // so we can't compare exact signature bytes. Instead we verify the produced
        // signature with the public key.
        let privPEM = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
        -----END PRIVATE KEY-----
        """
        let pubPEM = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
        -----END PUBLIC KEY-----
        """

        let privDER = try PEMUtils.decodePEM(privPEM)
        let pubDER = try PEMUtils.decodePEM(pubPEM)
        let signer = try Ed25519SigningKey(keyId: "test-key-ed25519", pkcs8DER: privDER)
        let verifier = try Ed25519VerifyingKey(keyId: "test-key-ed25519", spkiDER: pubDER)

        let baseStr = [
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT",
            "\"@method\": POST",
            "\"@path\": /foo",
            "\"@authority\": example.com",
            "\"content-type\": application/json",
            "\"content-length\": 18",
            "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
        ].joined(separator: "\n")

        let sig = try signer.sign(Data(baseStr.utf8))
        let valid = try verifier.verify(Data(baseStr.utf8), signature: sig)
        #expect(valid)
    }

    @Test("Ed25519 verify known signature from PEM")
    func ed25519VerifyFromPEM() throws {
        let pubPEM = """
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
        -----END PUBLIC KEY-----
        """
        let der = try PEMUtils.decodePEM(pubPEM)
        let verifier = try Ed25519VerifyingKey(keyId: "test-key-ed25519", spkiDER: der)

        let baseStr = [
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT",
            "\"@method\": POST",
            "\"@path\": /foo",
            "\"@authority\": example.com",
            "\"content-type\": application/json",
            "\"content-length\": 18",
            "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
        ].joined(separator: "\n")

        // B.2.6 expected signature (produced by Go/Java which use standard Ed25519)
        let sig = Data(base64Encoded: "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==")!
        let valid = try verifier.verify(Data(baseStr.utf8), signature: sig)
        #expect(valid)
    }

    @Test("RSA-PSS sign and verify round-trip")
    func rsaPSSRoundtrip() throws {
        // Generate a new RSA key pair with the Security framework.
        let parameters: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var error: Unmanaged<CFError>?
        guard let secPrivKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            throw HttpSigError.invalidKey("failed to generate RSA key: \(error!.takeRetainedValue())")
        }
        guard let secPubKey = SecKeyCopyPublicKey(secPrivKey) else {
            throw HttpSigError.invalidKey("failed to extract public key")
        }

        let signer = RSAPSSSigningKey(keyId: "test-rsa", secKey: secPrivKey)
        let verifier = RSAPSSVerifyingKey(keyId: "test-rsa", secKey: secPubKey)

        let data = Data("test message for RSA-PSS".utf8)
        let sig = try signer.sign(data)
        let valid = try verifier.verify(data, signature: sig)
        #expect(valid)

        // Tampered signature
        var tampered = sig
        tampered[0] ^= 0xFF
        let invalid = try verifier.verify(data, signature: tampered)
        #expect(!invalid)
    }

    @Test("RSA-PSS verify known signature from test vectors")
    func rsaPSSVerifyKnownSignature() throws {
        // Load the public key from the test vectors
        let pubPEM = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
        +QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
        oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
        gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
        Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
        aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
        2wIDAQAB
        -----END PUBLIC KEY-----
        """
        let pubDER = try PEMUtils.decodePEM(pubPEM)
        let verifier = try RSAPSSVerifyingKey(keyId: "test-key-rsa-pss", spkiDER: pubDER)

        // B.2.1 signature base
        let baseStr = "\"@signature-params\": ();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\""
        let sigB64 = "d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q=="
        let sig = Data(base64Encoded: sigB64)!
        let valid = try verifier.verify(Data(baseStr.utf8), signature: sig)
        #expect(valid)
    }
}
