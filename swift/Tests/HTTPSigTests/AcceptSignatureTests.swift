import Foundation
import Testing
@testable import HTTPSig

@Suite("AcceptSignature")
struct AcceptSignatureTests {

    // MARK: - Round-trip

    @Test("Round-trip: build then parse preserves requirements")
    func roundTrip() throws {
        let reqs = SignatureRequirements(
            components: [
                ComponentIdentifier("@method"),
                ComponentIdentifier("@authority"),
                ComponentIdentifier("content-digest"),
            ],
            keyId: "server-key-1",
            algorithm: .ecdsaP256Sha256,
            tag: "myapp",
            requireCreated: true,
            requireExpires: true
        )

        let header = AcceptSignature.build(["sig1": reqs])
        let parsed = try AcceptSignature.parse(header)

        #expect(parsed.count == 1)
        let sig1 = try #require(parsed["sig1"])
        #expect(sig1.components.count == 3)
        #expect(sig1.components[0].name == "@method")
        #expect(sig1.components[1].name == "@authority")
        #expect(sig1.components[2].name == "content-digest")
        #expect(sig1.keyId == "server-key-1")
        #expect(sig1.algorithm == .ecdsaP256Sha256)
        #expect(sig1.tag == "myapp")
        #expect(sig1.requireCreated == true)
        #expect(sig1.requireExpires == true)
    }

    // MARK: - RFC-style example

    @Test("Parse RFC-style Accept-Signature example")
    func parseRFCExample() throws {
        let header = """
        sig1=("@method" "@authority" "content-digest");keyid="server-key-1";alg="ecdsa-p256-sha256";created;expires;tag="myapp"
        """
        let parsed = try AcceptSignature.parse(header)

        #expect(parsed.count == 1)
        let sig1 = try #require(parsed["sig1"])
        #expect(sig1.components.count == 3)
        #expect(sig1.components[0].name == "@method")
        #expect(sig1.components[1].name == "@authority")
        #expect(sig1.components[2].name == "content-digest")
        #expect(sig1.keyId == "server-key-1")
        #expect(sig1.algorithm == .ecdsaP256Sha256)
        #expect(sig1.tag == "myapp")
        #expect(sig1.requireCreated == true)
        #expect(sig1.requireExpires == true)
    }

    // MARK: - Multiple entries

    @Test("Multiple entries round-trip")
    func multipleEntries() throws {
        let entries: [String: SignatureRequirements] = [
            "sig1": SignatureRequirements(
                components: [ComponentIdentifier("@method")],
                keyId: "key-1",
                algorithm: .ecdsaP256Sha256
            ),
            "sig2": SignatureRequirements(
                components: [ComponentIdentifier("@authority"), ComponentIdentifier("@path")],
                keyId: "key-2",
                algorithm: .ed25519,
                tag: "proxy"
            ),
        ]

        let header = AcceptSignature.build(entries)
        let parsed = try AcceptSignature.parse(header)

        #expect(parsed.count == 2)

        let sig1 = try #require(parsed["sig1"])
        #expect(sig1.components.count == 1)
        #expect(sig1.components[0].name == "@method")
        #expect(sig1.keyId == "key-1")
        #expect(sig1.algorithm == .ecdsaP256Sha256)

        let sig2 = try #require(parsed["sig2"])
        #expect(sig2.components.count == 2)
        #expect(sig2.components[0].name == "@authority")
        #expect(sig2.components[1].name == "@path")
        #expect(sig2.keyId == "key-2")
        #expect(sig2.algorithm == .ed25519)
        #expect(sig2.tag == "proxy")
    }

    // MARK: - Component with params

    @Test("Component with params (@query-param;name)")
    func componentWithParams() throws {
        var nameParam = SFVParams()
        nameParam.set("name", .string("foo"))
        let reqs = SignatureRequirements(
            components: [
                ComponentIdentifier("@query-param", params: nameParam),
            ]
        )

        let header = AcceptSignature.build(["sig1": reqs])
        let parsed = try AcceptSignature.parse(header)

        let sig1 = try #require(parsed["sig1"])
        #expect(sig1.components.count == 1)
        #expect(sig1.components[0].name == "@query-param")
        #expect(sig1.components[0].paramString("name") == "foo")
    }

    // MARK: - Empty components

    @Test("Empty components list")
    func emptyComponents() throws {
        let reqs = SignatureRequirements(
            keyId: "some-key"
        )

        let header = AcceptSignature.build(["sig1": reqs])
        let parsed = try AcceptSignature.parse(header)

        let sig1 = try #require(parsed["sig1"])
        #expect(sig1.components.isEmpty)
        #expect(sig1.keyId == "some-key")
    }

    // MARK: - signatureParameters conversion

    @Test("signatureParameters conversion")
    func signatureParametersConversion() throws {
        let reqs = SignatureRequirements(
            components: [
                ComponentIdentifier("@method"),
                ComponentIdentifier("@authority"),
            ],
            keyId: "my-key",
            algorithm: .hmacSha256,
            tag: "myapp"
        )

        let params = reqs.signatureParameters(
            created: 1618884473,
            expires: 1618884573,
            nonce: "abc123"
        )

        #expect(params.components.count == 2)
        #expect(params.components[0].name == "@method")
        #expect(params.components[1].name == "@authority")
        #expect(params.keyId == "my-key")
        #expect(params.algorithm == .hmacSha256)
        #expect(params.tag == "myapp")
        #expect(params.created == 1618884473)
        #expect(params.expires == 1618884573)
        #expect(params.nonce == "abc123")
    }

    // MARK: - Verifier with requirements

    @Test("Verifier filters by requirements keyId")
    func verifierFiltersByKeyId() throws {
        let secretB64 = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
        let secret = Data(base64Encoded: secretB64)!
        let key = HMACSHA256Key(keyId: "test-shared-secret", secret: secret)

        let params = SignatureParameters(
            components: [
                ComponentIdentifier("@method"),
                ComponentIdentifier("@authority"),
            ],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let msg = RawMessage.request(
            method: "POST",
            url: URL(string: "https://example.com/foo")!,
            headers: [("Host", "example.com")]
        )

        let result = try Signer.sign(msg: msg, label: "sig1", params: params, key: key)
        let sigInputHeader = Signer.signatureInputHeader(result)
        let sigHeader = Signer.signatureHeader(result)

        let signedMsg = RawMessage.request(
            method: "POST",
            url: URL(string: "https://example.com/foo")!,
            headers: [
                ("Host", "example.com"),
                ("Signature-Input", sigInputHeader),
                ("Signature", sigHeader),
            ]
        )

        let provider = FixedKeyProvider(key: key)

        // Should succeed: matching keyId
        let verifyResult = try Verifier.verify(
            msg: signedMsg,
            provider: provider,
            options: VerifyOptions(
                requirements: SignatureRequirements(
                    components: [ComponentIdentifier("@method")],
                    keyId: "test-shared-secret"
                ),
                rejectExpired: false
            )
        )
        #expect(verifyResult.label == "sig1")

        // Should fail: wrong keyId
        #expect(throws: HttpSigError.self) {
            try Verifier.verify(
                msg: signedMsg,
                provider: provider,
                options: VerifyOptions(
                    requirements: SignatureRequirements(
                        keyId: "wrong-key"
                    ),
                    rejectExpired: false
                )
            )
        }
    }

    @Test("Verifier filters by requirements algorithm")
    func verifierFiltersByAlgorithm() throws {
        let secretB64 = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
        let secret = Data(base64Encoded: secretB64)!
        let key = HMACSHA256Key(keyId: "test-shared-secret", secret: secret)

        let params = SignatureParameters(
            components: [ComponentIdentifier("@method")],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let msg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.com/")!,
            headers: [("Host", "example.com")]
        )

        let result = try Signer.sign(msg: msg, label: "sig1", params: params, key: key)
        let sigInputHeader = Signer.signatureInputHeader(result)
        let sigHeader = Signer.signatureHeader(result)

        let signedMsg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.com/")!,
            headers: [
                ("Host", "example.com"),
                ("Signature-Input", sigInputHeader),
                ("Signature", sigHeader),
            ]
        )

        let provider = FixedKeyProvider(key: key)

        // Should fail: wrong algorithm requirement
        #expect(throws: HttpSigError.self) {
            try Verifier.verify(
                msg: signedMsg,
                provider: provider,
                options: VerifyOptions(
                    requirements: SignatureRequirements(
                        algorithm: .ed25519
                    ),
                    rejectExpired: false
                )
            )
        }
    }

    @Test("Verifier filters by requirements tag")
    func verifierFiltersByTag() throws {
        let secretB64 = "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
        let secret = Data(base64Encoded: secretB64)!
        let key = HMACSHA256Key(keyId: "test-shared-secret", secret: secret)

        let params = SignatureParameters(
            components: [ComponentIdentifier("@method")],
            keyId: "test-shared-secret",
            created: 1618884473,
            tag: "myapp"
        )

        let msg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.com/")!,
            headers: [("Host", "example.com")]
        )

        let result = try Signer.sign(msg: msg, label: "sig1", params: params, key: key)
        let sigInputHeader = Signer.signatureInputHeader(result)
        let sigHeader = Signer.signatureHeader(result)

        let signedMsg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.com/")!,
            headers: [
                ("Host", "example.com"),
                ("Signature-Input", sigInputHeader),
                ("Signature", sigHeader),
            ]
        )

        let provider = FixedKeyProvider(key: key)

        // Should succeed: matching tag
        let verifyResult = try Verifier.verify(
            msg: signedMsg,
            provider: provider,
            options: VerifyOptions(
                requirements: SignatureRequirements(tag: "myapp"),
                rejectExpired: false
            )
        )
        #expect(verifyResult.label == "sig1")

        // Should fail: wrong tag
        #expect(throws: HttpSigError.self) {
            try Verifier.verify(
                msg: signedMsg,
                provider: provider,
                options: VerifyOptions(
                    requirements: SignatureRequirements(tag: "other"),
                    rejectExpired: false
                )
            )
        }
    }

    // MARK: - Defaults

    @Test("SignatureRequirements defaults")
    func defaults() {
        let reqs = SignatureRequirements()
        #expect(reqs.components.isEmpty)
        #expect(reqs.keyId == nil)
        #expect(reqs.algorithm == nil)
        #expect(reqs.tag == nil)
        #expect(reqs.requireCreated == false)
        #expect(reqs.requireExpires == false)
    }

    @Test("Build with no params produces minimal output")
    func buildMinimal() throws {
        let reqs = SignatureRequirements(
            components: [ComponentIdentifier("@method")]
        )
        let header = AcceptSignature.build(["sig1": reqs])
        #expect(header == "sig1=(\"@method\")")
    }
}
