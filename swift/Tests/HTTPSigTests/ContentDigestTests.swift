import Foundation
import Testing
@testable import HTTPSig

@Suite("Content Digest")
struct ContentDigestTests {

    @Test("Compute SHA-256 digest")
    func computeSha256() throws {
        let body = Data("{\"hello\": \"world\"}".utf8)
        let result = ContentDigest.compute(body: body, algorithm: .sha256)
        #expect(result.hasPrefix("sha-256=:"))
        #expect(result.hasSuffix(":"))
    }

    @Test("Compute SHA-512 digest")
    func computeSha512() throws {
        let body = Data("{\"hello\": \"world\"}".utf8)
        let result = ContentDigest.compute(body: body, algorithm: .sha512)
        #expect(result.hasPrefix("sha-512=:"))
        #expect(result.hasSuffix(":"))

        // Verify against the known value from the test vectors
        #expect(result == "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:")
    }

    @Test("Verify correct digest")
    func verifyCorrectDigest() throws {
        let body = Data("{\"hello\": \"world\"}".utf8)
        let headerValue = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        let result = try ContentDigest.verify(body: body, headerValue: headerValue)
        #expect(result)
    }

    @Test("Verify incorrect digest")
    func verifyIncorrectDigest() throws {
        let body = Data("wrong body".utf8)
        let headerValue = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        let result = try ContentDigest.verify(body: body, headerValue: headerValue)
        #expect(!result)
    }

    @Test("Compute and verify round-trip")
    func computeVerifyRoundtrip() throws {
        let body = Data("some arbitrary data".utf8)
        let header = ContentDigest.compute(body: body, algorithm: .sha256)
        let valid = try ContentDigest.verify(body: body, headerValue: header)
        #expect(valid)
    }
}
