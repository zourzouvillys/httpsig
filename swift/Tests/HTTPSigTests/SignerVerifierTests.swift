import Foundation
import Testing
import CryptoKit
@testable import HTTPSig

/// A simple key provider that returns a fixed key.
struct FixedKeyProvider: KeyProvider {
    let key: any VerifyingKey

    func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? {
        if keyId == key.keyId { return key }
        return nil
    }
}

@Suite("Signer & Verifier")
struct SignerVerifierTests {

    static let testRequest = RawMessage.request(
        method: "POST",
        url: URL(string: "https://example.com/foo?param=Value&Pet=dog")!,
        headers: [
            ("Host", "example.com"),
            ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("Content-Type", "application/json"),
            ("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"),
            ("Content-Length", "18"),
        ]
    )

    @Test("HMAC sign and verify round-trip through headers")
    func hmacSignVerifyRoundtrip() throws {
        let secretB64 = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
        let secret = Data(base64Encoded: secretB64)!
        let key = HMACSHA256Key(keyId: "test-shared-secret", secret: secret)

        let params = SignatureParameters(
            components: [
                ComponentIdentifier("date"),
                ComponentIdentifier("@authority"),
                ComponentIdentifier("content-type"),
            ],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let result = try Signer.sign(
            msg: Self.testRequest,
            label: "sig-b25",
            params: params,
            key: key
        )

        // Check the expected signature matches B.2.5
        #expect(result.signature.base64EncodedString() == "pxcQw6G3AjtMBQjwo8XzkZf/bws5LelbaMk5rGIGtE8=")

        // Build header values
        let sigInputHeader = Signer.signatureInputHeader(result)
        let sigHeader = Signer.signatureHeader(result)

        #expect(sigInputHeader == "sig-b25=(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"")

        // Now verify by constructing a message with the signature headers
        let signedMsg = RawMessage.request(
            method: "POST",
            url: URL(string: "https://example.com/foo?param=Value&Pet=dog")!,
            headers: [
                ("Host", "example.com"),
                ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
                ("Content-Type", "application/json"),
                ("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"),
                ("Content-Length", "18"),
                ("Signature-Input", sigInputHeader),
                ("Signature", sigHeader),
            ]
        )

        let provider = FixedKeyProvider(key: key)
        let verifyResult = try Verifier.verify(
            msg: signedMsg,
            provider: provider,
            options: VerifyOptions(rejectExpired: false)
        )
        #expect(verifyResult.label == "sig-b25")
        #expect(verifyResult.keyId == "test-shared-secret")
        #expect(verifyResult.algorithm == .hmacSha256)
        #expect(verifyResult.created == 1618884473)
    }

    @Test("Ed25519 sign and verify round-trip")
    func ed25519SignVerify() throws {
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

        let params = SignatureParameters(
            components: [
                ComponentIdentifier("date"),
                ComponentIdentifier("@method"),
                ComponentIdentifier("@path"),
                ComponentIdentifier("@authority"),
                ComponentIdentifier("content-type"),
                ComponentIdentifier("content-length"),
            ],
            keyId: "test-key-ed25519",
            created: 1618884473
        )

        let result = try Signer.sign(
            msg: Self.testRequest,
            label: "sig-b26",
            params: params,
            key: signer
        )

        // CryptoKit may produce randomized Ed25519 signatures for side-channel
        // protection, so we verify instead of comparing exact bytes.
        #expect(result.signature.count == 64)

        // Verify
        let sigInputHeader = Signer.signatureInputHeader(result)
        let sigHeader = Signer.signatureHeader(result)

        let signedMsg = RawMessage.request(
            method: "POST",
            url: URL(string: "https://example.com/foo?param=Value&Pet=dog")!,
            headers: [
                ("Host", "example.com"),
                ("Date", "Tue, 20 Apr 2021 02:07:55 GMT"),
                ("Content-Type", "application/json"),
                ("Content-Digest", "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"),
                ("Content-Length", "18"),
                ("Signature-Input", sigInputHeader),
                ("Signature", sigHeader),
            ]
        )

        let provider = FixedKeyProvider(key: verifier)
        let verifyResult = try Verifier.verify(
            msg: signedMsg,
            provider: provider,
            options: VerifyOptions(rejectExpired: false)
        )
        #expect(verifyResult.label == "sig-b26")
        #expect(verifyResult.keyId == "test-key-ed25519")
    }

    @Test("Signature header formatting")
    func signatureHeaderFormatting() throws {
        let result = SignResult(
            label: "sig1",
            signatureInput: "(\"@method\");created=123",
            signature: Data("test".utf8)
        )
        let header = Signer.signatureHeader(result)
        #expect(header == "sig1=:dGVzdA==:")
    }

    @Test("Signature-Input header formatting")
    func signatureInputHeaderFormatting() throws {
        let result = SignResult(
            label: "sig1",
            signatureInput: "(\"@method\");created=123",
            signature: Data()
        )
        let header = Signer.signatureInputHeader(result)
        #expect(header == "sig1=(\"@method\");created=123")
    }

    @Test("Missing Signature-Input header fails verification")
    func missingSignatureInput() throws {
        let msg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.com/")!,
            headers: []
        )
        let provider = FixedKeyProvider(
            key: HMACSHA256Key(keyId: "k", secret: Data("s".utf8))
        )
        #expect(throws: HttpSigError.self) {
            try Verifier.verify(msg: msg, provider: provider)
        }
    }
}
