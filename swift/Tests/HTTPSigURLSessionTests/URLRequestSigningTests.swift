import Foundation
import Testing
import HTTPSig
import HTTPSigURLSession

@Suite("URLRequest Signing")
struct URLRequestSigningTests {

    private static let secret = Data(base64Encoded:
        "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
    )!

    private static let key = HMACSHA256Key(keyId: "test-shared-secret", secret: secret)

    @Test("signed() adds Signature and Signature-Input headers")
    func signedAddsHeaders() throws {
        var request = URLRequest(url: URL(string: "https://example.com/foo")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let params = SignatureParameters(
            components: [
                ComponentIdentifier("@method"),
                ComponentIdentifier("@path"),
                ComponentIdentifier("content-type"),
            ],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let signed = try request.signed(label: "sig1", params: params, key: Self.key)

        let sigInput = signed.value(forHTTPHeaderField: "Signature-Input")
        let sig = signed.value(forHTTPHeaderField: "Signature")

        #expect(sigInput != nil)
        #expect(sig != nil)
        #expect(sigInput!.hasPrefix("sig1="))
        #expect(sig!.hasPrefix("sig1=:"))
        #expect(sig!.hasSuffix(":"))
    }

    @Test("signed() preserves original headers")
    func signedPreservesHeaders() throws {
        var request = URLRequest(url: URL(string: "https://example.com/bar")!)
        request.httpMethod = "GET"
        request.setValue("text/plain", forHTTPHeaderField: "Accept")

        let params = SignatureParameters(
            components: [ComponentIdentifier("@method")],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let signed = try request.signed(label: "sig1", params: params, key: Self.key)

        #expect(signed.value(forHTTPHeaderField: "Accept") == "text/plain")
        #expect(signed.httpMethod == "GET")
    }

    @Test("sign and verify round-trip through URLRequest")
    func signAndVerifyRoundtrip() throws {
        var request = URLRequest(url: URL(string: "https://example.com/foo?param=Value&Pet=dog")!)
        request.httpMethod = "POST"
        request.setValue("example.com", forHTTPHeaderField: "Host")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let params = SignatureParameters(
            components: [
                ComponentIdentifier("@method"),
                ComponentIdentifier("@authority"),
                ComponentIdentifier("content-type"),
            ],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let signed = try request.signed(label: "sig1", params: params, key: Self.key)

        // Now build a RawMessage from the signed URLRequest and verify it
        var headers: [(String, String)] = []
        for (name, value) in signed.allHTTPHeaderFields ?? [:] {
            headers.append((name, value))
        }

        let msg = RawMessage.request(
            method: signed.httpMethod ?? "GET",
            url: signed.url!,
            headers: headers
        )

        struct Provider: KeyProvider {
            let key: any VerifyingKey
            func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? {
                keyId == key.keyId ? key : nil
            }
        }

        let result = try Verifier.verify(
            msg: msg,
            provider: Provider(key: Self.key),
            options: VerifyOptions(rejectExpired: false)
        )
        #expect(result.label == "sig1")
        #expect(result.keyId == "test-shared-secret")
    }

    @Test("URLResponseMessage exposes status code and headers")
    func responseMessage() throws {
        let response = HTTPURLResponse(
            url: URL(string: "https://example.com/")!,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "text/html", "X-Custom": "value"]
        )!

        let msg = URLResponseMessage(response)

        #expect(msg.isRequest == false)
        #expect(msg.statusCode == 200)
        #expect(msg.headerValues(name: "content-type") == ["text/html"])
        #expect(msg.headerValues(name: "x-custom") == ["value"])
        #expect(msg.headerValues(name: "nonexistent").isEmpty)
    }
}
