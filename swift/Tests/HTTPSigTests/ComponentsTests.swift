import Foundation
import Testing
@testable import HTTPSig

@Suite("Components")
struct ComponentsTests {

    // The standard test message used across vectors.
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

    @Test("@method")
    func extractMethod() throws {
        let value = try Components.extract(ComponentIdentifier("@method"), from: Self.testRequest)
        #expect(value == "POST")
    }

    @Test("@target-uri")
    func extractTargetURI() throws {
        let value = try Components.extract(ComponentIdentifier("@target-uri"), from: Self.testRequest)
        #expect(value == "https://example.com/foo?param=Value&Pet=dog")
    }

    @Test("@authority")
    func extractAuthority() throws {
        let value = try Components.extract(ComponentIdentifier("@authority"), from: Self.testRequest)
        #expect(value == "example.com")
    }

    @Test("@scheme")
    func extractScheme() throws {
        let value = try Components.extract(ComponentIdentifier("@scheme"), from: Self.testRequest)
        #expect(value == "https")
    }

    @Test("@path")
    func extractPath() throws {
        let value = try Components.extract(ComponentIdentifier("@path"), from: Self.testRequest)
        #expect(value == "/foo")
    }

    @Test("@query")
    func extractQuery() throws {
        let value = try Components.extract(ComponentIdentifier("@query"), from: Self.testRequest)
        #expect(value == "?param=Value&Pet=dog")
    }

    @Test("@query-param")
    func extractQueryParam() throws {
        let cid = ComponentIdentifier.queryParam("param")
        let value = try Components.extract(cid, from: Self.testRequest)
        #expect(value == "Value")

        let cid2 = ComponentIdentifier.queryParam("Pet")
        let value2 = try Components.extract(cid2, from: Self.testRequest)
        #expect(value2 == "dog")
    }

    @Test("Header field")
    func extractHeader() throws {
        let value = try Components.extract(
            ComponentIdentifier("content-type"),
            from: Self.testRequest
        )
        #expect(value == "application/json")
    }

    @Test("Header field case-insensitive")
    func extractHeaderCaseInsensitive() throws {
        let value = try Components.extract(
            ComponentIdentifier("Content-Type"),
            from: Self.testRequest
        )
        #expect(value == "application/json")
    }

    @Test("Missing header throws")
    func missingHeaderThrows() throws {
        #expect(throws: HttpSigError.self) {
            try Components.extract(
                ComponentIdentifier("x-nonexistent"),
                from: Self.testRequest
            )
        }
    }

    @Test("@status on response")
    func extractStatus() throws {
        let response = RawMessage.response(
            statusCode: 200,
            headers: [("Content-Type", "application/json")]
        )
        let value = try Components.extract(ComponentIdentifier("@status"), from: response)
        #expect(value == "200")
    }

    @Test("@status on request throws")
    func statusOnRequestThrows() throws {
        #expect(throws: HttpSigError.self) {
            try Components.extract(ComponentIdentifier("@status"), from: Self.testRequest)
        }
    }

    @Test("@method on response throws")
    func methodOnResponseThrows() throws {
        let response = RawMessage.response(statusCode: 200, headers: [])
        #expect(throws: HttpSigError.self) {
            try Components.extract(ComponentIdentifier("@method"), from: response)
        }
    }

    @Test("Multiple header values joined")
    func multipleHeaderValues() throws {
        let msg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.org/demo?name1=Value1&Name2=value2")!,
            headers: [
                ("Host", "example.org"),
                ("Accept", "application/json"),
                ("Accept", "*/*"),
            ]
        )
        let value = try Components.extract(ComponentIdentifier("accept"), from: msg)
        #expect(value == "application/json, */*")
    }

    @Test("@request-target")
    func extractRequestTarget() throws {
        let value = try Components.extract(
            ComponentIdentifier("@request-target"),
            from: Self.testRequest
        )
        #expect(value == "/foo?param=Value&Pet=dog")
    }
}
