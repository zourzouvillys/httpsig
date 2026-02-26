import Foundation
import Testing
@testable import HTTPSig

/// A key provider that always returns the given key regardless of algorithm hint.
private struct StaticKeyProvider: KeyProvider {
    let key: any VerifyingKey

    func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? {
        if keyId == key.keyId { return key }
        return nil
    }
}

/// Helper: sign a message and return a new message with the signature headers attached.
private func signAndAttachHeaders(
    method: String = "GET",
    url: URL = URL(string: "https://example.com/test")!,
    baseHeaders: [(String, String)] = [("Host", "example.com")],
    params: SignatureParameters,
    key: some SigningKey,
    label: String = "sig1"
) throws -> RawMessage {
    let msg = RawMessage.request(method: method, url: url, headers: baseHeaders)
    let result = try Signer.sign(msg: msg, label: label, params: params, key: key)
    let sigInputHeader = Signer.signatureInputHeader(result)
    let sigHeader = Signer.signatureHeader(result)
    return RawMessage.request(
        method: method,
        url: url,
        headers: baseHeaders + [
            ("Signature-Input", sigInputHeader),
            ("Signature", sigHeader),
        ]
    )
}

// MARK: - Future-dated signature rejection

@Suite("Security: future-dated signatures")
struct FutureDatedSignatureTests {

    static let key = HMACSHA256Key(keyId: "clock-test", secret: Data("secret-key-material-for-clock-skew-test".utf8))

    @Test("Reject signature created 1 hour in the future with tight skew tolerance")
    func rejectFutureDatedWithTightSkew() throws {
        let futureCreated = Int64(Date().timeIntervalSince1970) + 3600

        let params = SignatureParameters(
            components: [ComponentIdentifier("@method")],
            keyId: "clock-test",
            created: futureCreated
        )

        let signedMsg = try signAndAttachHeaders(params: params, key: Self.key)
        let provider = StaticKeyProvider(key: Self.key)

        // The verifier wraps per-label errors into invalidSignature, but the
        // underlying cause is signatureFutureDated. Check the wrapper contains it.
        do {
            _ = try Verifier.verify(
                msg: signedMsg,
                provider: provider,
                options: VerifyOptions(maxClockSkew: 30, rejectExpired: false)
            )
            Issue.record("Expected verification to throw, but it succeeded")
        } catch let error as HttpSigError {
            switch error {
            case .invalidSignature(let msg):
                #expect(msg.contains("signatureFutureDated"))
            case .signatureFutureDated:
                break // also acceptable if the verifier ever propagates directly
            default:
                Issue.record("Expected signatureFutureDated-related error, got: \(error)")
            }
        }
    }

    @Test("Accept future-dated signature when skew tolerance is large enough")
    func acceptFutureDatedWithLargeSkew() throws {
        let futureCreated = Int64(Date().timeIntervalSince1970) + 3600

        let params = SignatureParameters(
            components: [ComponentIdentifier("@method")],
            keyId: "clock-test",
            created: futureCreated
        )

        let signedMsg = try signAndAttachHeaders(params: params, key: Self.key)
        let provider = StaticKeyProvider(key: Self.key)

        let result = try Verifier.verify(
            msg: signedMsg,
            provider: provider,
            options: VerifyOptions(maxClockSkew: 7200, rejectExpired: false)
        )

        #expect(result.keyId == "clock-test")
        #expect(result.created == futureCreated)
    }

    @Test("Accept future-dated signature when maxClockSkew is nil (no check)")
    func acceptFutureDatedWithNilSkew() throws {
        let futureCreated = Int64(Date().timeIntervalSince1970) + 3600

        let params = SignatureParameters(
            components: [ComponentIdentifier("@method")],
            keyId: "clock-test",
            created: futureCreated
        )

        let signedMsg = try signAndAttachHeaders(params: params, key: Self.key)
        let provider = StaticKeyProvider(key: Self.key)

        let result = try Verifier.verify(
            msg: signedMsg,
            provider: provider,
            options: VerifyOptions(maxClockSkew: nil, rejectExpired: false)
        )

        #expect(result.keyId == "clock-test")
        #expect(result.created == futureCreated)
    }
}

// MARK: - Algorithm mismatch rejection

@Suite("Security: algorithm mismatch")
struct AlgorithmMismatchTests {

    @Test("Reject when Signature-Input claims ed25519 but key is HMAC-SHA256")
    func rejectAlgorithmMismatch() throws {
        let key = HMACSHA256Key(keyId: "mismatch-key", secret: Data("test-secret-for-alg-mismatch".utf8))

        let params = SignatureParameters(
            components: [ComponentIdentifier("@method")],
            keyId: "mismatch-key",
            created: Int64(Date().timeIntervalSince1970)
        )

        // Sign the message normally (HMAC-SHA256)
        let msg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.com/test")!,
            headers: [("Host", "example.com")]
        )
        let result = try Signer.sign(msg: msg, label: "sig1", params: params, key: key)

        // Tamper: replace the alg parameter (or inject one) to claim ed25519
        let sigInput = Signer.signatureInputHeader(result)
        let tamperedSigInput: String
        if sigInput.contains("alg=") {
            // Replace existing alg parameter
            tamperedSigInput = sigInput.replacingOccurrences(
                of: "alg=\"hmac-sha256\"",
                with: "alg=\"ed25519\""
            )
        } else {
            // No alg was present (SignatureParameters.algorithm was nil), so inject one.
            // Insert alg="ed25519" before the last parameter or at the end.
            // The format is: sig1=("@method");created=...;keyid="..."
            // We append ;alg="ed25519" before the end.
            tamperedSigInput = sigInput + ";alg=\"ed25519\""
        }

        let sigHeader = Signer.signatureHeader(result)

        let signedMsg = RawMessage.request(
            method: "GET",
            url: URL(string: "https://example.com/test")!,
            headers: [
                ("Host", "example.com"),
                ("Signature-Input", tamperedSigInput),
                ("Signature", sigHeader),
            ]
        )

        let provider = StaticKeyProvider(key: key)

        // Verification should fail because the key's algorithm (hmac-sha256)
        // doesn't match what the Signature-Input claims (ed25519).
        #expect(throws: HttpSigError.self) {
            try Verifier.verify(
                msg: signedMsg,
                provider: provider,
                options: VerifyOptions(rejectExpired: false)
            )
        }
    }
}

// MARK: - VerifyResult returns key's algorithm

@Suite("Security: VerifyResult algorithm")
struct VerifyResultAlgorithmTests {

    @Test("VerifyResult.algorithm matches the key's algorithm")
    func verifyResultReturnsKeyAlgorithm() throws {
        let key = HMACSHA256Key(keyId: "alg-check", secret: Data("secret-for-alg-result-check".utf8))

        let params = SignatureParameters(
            components: [ComponentIdentifier("@method"), ComponentIdentifier("@authority")],
            keyId: "alg-check",
            created: Int64(Date().timeIntervalSince1970)
        )

        let signedMsg = try signAndAttachHeaders(params: params, key: key)
        let provider = StaticKeyProvider(key: key)

        let result = try Verifier.verify(
            msg: signedMsg,
            provider: provider,
            options: VerifyOptions(rejectExpired: false)
        )

        #expect(result.algorithm == key.algorithm)
        #expect(result.algorithm == .hmacSha256)
    }
}
