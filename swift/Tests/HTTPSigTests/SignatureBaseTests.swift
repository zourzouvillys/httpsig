import Foundation
import Testing
@testable import HTTPSig

@Suite("Signature Base")
struct SignatureBaseTests {

    // Standard test request from RFC 9421 Appendix B.
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

    @Test("B.2.1 - Minimal signature base (empty components)")
    func b21MinimalBase() throws {
        let params = SignatureParameters(
            components: [],
            keyId: "test-key-rsa-pss",
            created: 1618884473,
            nonce: "b3k2pp5k7z-50gnwp.yemd"
        )

        let result = try SignatureBase.build(msg: Self.testRequest, params: params)
        let expected = "\"@signature-params\": ();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\""
        #expect(String(data: result.base, encoding: .utf8) == expected)
    }

    @Test("B.2.6 - Ed25519 signature base")
    func b26Ed25519Base() throws {
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

        let result = try SignatureBase.build(msg: Self.testRequest, params: params)
        let expectedBase = [
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT",
            "\"@method\": POST",
            "\"@path\": /foo",
            "\"@authority\": example.com",
            "\"content-type\": application/json",
            "\"content-length\": 18",
            "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\"",
        ].joined(separator: "\n")

        #expect(String(data: result.base, encoding: .utf8) == expectedBase)
    }

    @Test("B.2.5 - HMAC signature base")
    func b25HmacBase() throws {
        let params = SignatureParameters(
            components: [
                ComponentIdentifier("date"),
                ComponentIdentifier("@authority"),
                ComponentIdentifier("content-type"),
            ],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let result = try SignatureBase.build(msg: Self.testRequest, params: params)
        let expectedBase = [
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT",
            "\"@authority\": example.com",
            "\"content-type\": application/json",
            "\"@signature-params\": (\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"",
        ].joined(separator: "\n")

        #expect(String(data: result.base, encoding: .utf8) == expectedBase)
    }

    @Test("B.2.4 - Response signature base")
    func b24ResponseBase() throws {
        let response = RawMessage.response(
            statusCode: 200,
            headers: [
                ("Date", "Tue, 20 Apr 2021 02:07:56 GMT"),
                ("Content-Type", "application/json"),
                ("Content-Digest", "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"),
                ("Content-Length", "23"),
            ]
        )

        let params = SignatureParameters(
            components: [
                ComponentIdentifier("@status"),
                ComponentIdentifier("content-type"),
                ComponentIdentifier("content-digest"),
                ComponentIdentifier("content-length"),
            ],
            keyId: "test-key-ecc-p256",
            created: 1618884473
        )

        let result = try SignatureBase.build(msg: response, params: params)
        let expectedBase = [
            "\"@status\": 200",
            "\"content-type\": application/json",
            "\"content-digest\": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
            "\"content-length\": 23",
            "\"@signature-params\": (\"@status\" \"content-type\" \"content-digest\" \"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\"",
        ].joined(separator: "\n")

        #expect(String(data: result.base, encoding: .utf8) == expectedBase)
    }

    @Test("Duplicate component detection")
    func duplicateComponent() throws {
        let params = SignatureParameters(
            components: [
                ComponentIdentifier("@method"),
                ComponentIdentifier("@method"),
            ]
        )
        #expect(throws: HttpSigError.self) {
            try SignatureBase.build(msg: Self.testRequest, params: params)
        }
    }

    @Test("Signature input value")
    func signatureInputValue() throws {
        let params = SignatureParameters(
            components: [
                ComponentIdentifier("date"),
                ComponentIdentifier("@authority"),
                ComponentIdentifier("content-type"),
            ],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let result = try SignatureBase.build(msg: Self.testRequest, params: params)
        #expect(result.signatureInput == "(\"date\" \"@authority\" \"content-type\");created=1618884473;keyid=\"test-shared-secret\"")
    }

    @Test("B.4 - Multi-value Accept header")
    func b4MultiValueAccept() throws {
        let msg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.org/demo?name1=Value1&Name2=value2")!,
            headers: [
                ("Host", "example.org"),
                ("Date", "Fri, 15 Jul 2022 14:24:55 GMT"),
                ("Accept", "application/json"),
                ("Accept", "*/*"),
            ]
        )

        let params = SignatureParameters(
            components: [
                ComponentIdentifier("@method"),
                ComponentIdentifier("@path"),
                ComponentIdentifier("@authority"),
                ComponentIdentifier("accept"),
            ],
            keyId: "test-key-ed25519",
            created: 1618884473
        )

        let result = try SignatureBase.build(msg: msg, params: params)
        let expectedBase = [
            "\"@method\": GET",
            "\"@path\": /demo",
            "\"@authority\": example.org",
            "\"accept\": application/json, */*",
            "\"@signature-params\": (\"@method\" \"@path\" \"@authority\" \"accept\");created=1618884473;keyid=\"test-key-ed25519\"",
        ].joined(separator: "\n")

        #expect(String(data: result.base, encoding: .utf8) == expectedBase)
    }
}
