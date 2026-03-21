import Foundation
import Testing
@testable import HTTPSig

/// Loads the shared RFC 9421 test vectors from testdata/vectors/ and validates:
/// - Signature base construction matches expected bytes
/// - Deterministic algorithms (HMAC) produce the exact expected signature
/// - All signatures round-trip through sign/verify
/// - Pre-computed verify-only signatures verify correctly
///
/// NOTE: Apple's CryptoKit uses randomized Ed25519 (for side-channel resistance),
/// so Ed25519 signatures won't match the reference vectors byte-for-byte.
/// We verify them through round-trip instead.
@Suite("RFC 9421 Test Vectors")
struct VectorTests {

    static let testdataPath = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()  // HTTPSigTests/
        .deletingLastPathComponent()  // Tests/
        .deletingLastPathComponent()  // swift/
        .deletingLastPathComponent()  // httpsig/
        .appendingPathComponent("testdata")

    static let vectorsPath = testdataPath.appendingPathComponent("vectors")
    static let keysPath = testdataPath.appendingPathComponent("keys")

    struct TestVector {
        let id: String
        let description: String
        let message: MessageData
        let requestMessage: MessageData?
        let label: String
        let keyId: String
        let algorithm: String
        let components: [ComponentIdentifier]
        let created: Int64?
        let nonce: String?
        let tag: String?
        let expectedBase: String
        let expectedSignatureInput: String
        let expectedSignature: String?
        let verifyOnlySignature: String?
        let deterministic: Bool
        let keyFile: String?
        let pubKeyFile: String?
    }

    struct MessageData {
        let type: String
        let method: String?
        let url: String?
        let statusCode: Int?
        let headers: [(String, String)]
    }

    // MARK: - Signature Base Tests

    @Test("Signature base matches expected", arguments: loadAllVectors())
    func signatureBase(vector: TestVector) throws {
        let msg = buildMessage(vector.message)
        let reqMsg = vector.requestMessage.map { buildMessage($0) }
        let params = buildParams(vector)
        let baseResult = try SignatureBase.build(msg: msg, params: params, reqMsg: reqMsg)
        let actual = String(data: baseResult.base, encoding: .utf8)!
        #expect(actual == vector.expectedBase, "Signature base mismatch for \(vector.id)")
    }

    // MARK: - Signature Input Tests

    @Test("Signature input matches expected", arguments: loadAllVectors())
    func signatureInput(vector: TestVector) throws {
        let params = buildParams(vector)
        let baseResult = try SignatureBase.build(
            msg: buildMessage(vector.message),
            params: params,
            reqMsg: vector.requestMessage.map { buildMessage($0) }
        )
        // expectedSignatureInput is "label=input", strip the label
        let expected = String(vector.expectedSignatureInput.drop(while: { $0 != "=" }).dropFirst())
        #expect(baseResult.signatureInput == expected, "Signature input mismatch for \(vector.id)")
    }

    // MARK: - Deterministic Signature Tests (HMAC only)

    @Test("HMAC deterministic signature matches expected", arguments: loadAllVectors().filter {
        $0.deterministic && $0.algorithm == "hmac-sha256"
    })
    func deterministicSignature(vector: TestVector) throws {
        let msg = buildMessage(vector.message)
        let reqMsg = vector.requestMessage.map { buildMessage($0) }
        let params = buildParams(vector)
        let signingKey = try loadSigningKey(vector)
        let result = try Signer.sign(msg: msg, label: vector.label, params: params, key: signingKey, reqMsg: reqMsg)
        let actual = result.signature.base64EncodedString()
        #expect(actual == vector.expectedSignature!, "Deterministic signature mismatch for \(vector.id)")
    }

    // MARK: - Verify Precomputed Tests

    @Test("Verify precomputed signature", arguments: loadAllVectors().filter { $0.verifyOnlySignature != nil })
    func verifyPrecomputed(vector: TestVector) throws {
        let reqMsg = vector.requestMessage.map { buildMessage($0) }
        let verifyingKey = try loadVerifyingKey(vector)

        // Build signed message with precomputed signature
        let sigInputVal = String(vector.expectedSignatureInput.drop(while: { $0 != "=" }).dropFirst())
        let sigInputHeader = "\(vector.label)=\(sigInputVal)"
        let sigHeader = "\(vector.label)=:\(vector.verifyOnlySignature!):"

        let signedMsg = addSignatureHeaders(vector.message, sigInputHeader: sigInputHeader, sigHeader: sigHeader)

        let provider = SingleKeyProvider(key: verifyingKey)
        let result = try Verifier.verify(msg: signedMsg, provider: provider, reqMsg: reqMsg)
        #expect(result.label == vector.label)
    }

    // MARK: - Round Trip Tests

    @Test("Sign and verify round trip", arguments: loadAllVectors())
    func roundTrip(vector: TestVector) throws {
        let msg = buildMessage(vector.message)
        let reqMsg = vector.requestMessage.map { buildMessage($0) }
        let params = buildParams(vector)
        let signingKey = try loadSigningKey(vector)
        let verifyingKey = try loadVerifyingKey(vector)

        let result = try Signer.sign(msg: msg, label: vector.label, params: params, key: signingKey, reqMsg: reqMsg)
        let sigInputHeader = Signer.signatureInputHeader(result)
        let sigHeader = Signer.signatureHeader(result)

        let signedMsg = addSignatureHeaders(vector.message, sigInputHeader: sigInputHeader, sigHeader: sigHeader)
        let provider = SingleKeyProvider(key: verifyingKey)
        let verifyResult = try Verifier.verify(msg: signedMsg, provider: provider, reqMsg: reqMsg)

        #expect(verifyResult.label == vector.label)
        #expect(verifyResult.keyId == vector.keyId)
    }

    // MARK: - Helpers

    struct SingleKeyProvider: KeyProvider {
        let key: any VerifyingKey
        func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)? {
            return key
        }
    }

    static func buildMessage(_ data: MessageData) -> RawMessage {
        if data.type == "request" {
            return RawMessage.request(
                method: data.method!,
                url: URL(string: data.url!)!,
                headers: data.headers
            )
        } else {
            return RawMessage.response(
                statusCode: data.statusCode!,
                headers: data.headers
            )
        }
    }

    func buildMessage(_ data: MessageData) -> RawMessage {
        Self.buildMessage(data)
    }

    func addSignatureHeaders(_ origMsg: MessageData, sigInputHeader: String, sigHeader: String) -> RawMessage {
        var headers = origMsg.headers
        headers.append(("Signature-Input", sigInputHeader))
        headers.append(("Signature", sigHeader))

        if origMsg.type == "request" {
            return RawMessage.request(
                method: origMsg.method!,
                url: URL(string: origMsg.url!)!,
                headers: headers
            )
        } else {
            return RawMessage.response(
                statusCode: origMsg.statusCode!,
                headers: headers
            )
        }
    }

    func buildParams(_ v: TestVector) -> SignatureParameters {
        SignatureParameters(
            components: v.components,
            keyId: v.keyId,
            created: v.created,
            nonce: v.nonce,
            tag: v.tag
        )
    }

    func loadSigningKey(_ v: TestVector) throws -> any SigningKey {
        let alg = Algorithm(rawValue: v.algorithm)!
        switch alg {
        case .hmacSha256:
            let b64 = try String(contentsOf: Self.keysPath.appendingPathComponent("hmac-secret.b64"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            let secret = Data(base64Encoded: b64)!
            return HMACSHA256Key(keyId: v.keyId, secret: secret)
        case .ed25519:
            let pem = try String(contentsOf: Self.testdataPath.appendingPathComponent(v.keyFile!), encoding: .utf8)
            let der = try PEMUtils.decodePEM(pem)
            return try Ed25519SigningKey(keyId: v.keyId, pkcs8DER: der)
        case .rsaPssSha512:
            let pem = try String(contentsOf: Self.testdataPath.appendingPathComponent(v.keyFile!), encoding: .utf8)
            let der = try PEMUtils.decodePEM(pem)
            return try RSAPSSSigningKey(keyId: v.keyId, pkcs8DER: der)
        case .ecdsaP256Sha256:
            let pem = try String(contentsOf: Self.testdataPath.appendingPathComponent(v.keyFile!), encoding: .utf8)
            let der = try PEMUtils.decodePEM(pem)
            return try ECDSAP256SigningKey(keyId: v.keyId, derRepresentation: der)
        default:
            fatalError("No test vector key for algorithm \(v.algorithm)")
        }
    }

    func loadVerifyingKey(_ v: TestVector) throws -> any VerifyingKey {
        let alg = Algorithm(rawValue: v.algorithm)!
        switch alg {
        case .hmacSha256:
            let b64 = try String(contentsOf: Self.keysPath.appendingPathComponent("hmac-secret.b64"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            let secret = Data(base64Encoded: b64)!
            return HMACSHA256Key(keyId: v.keyId, secret: secret)
        case .ed25519:
            let pem = try String(contentsOf: Self.testdataPath.appendingPathComponent(v.pubKeyFile!), encoding: .utf8)
            let der = try PEMUtils.decodePEM(pem)
            return try Ed25519VerifyingKey(keyId: v.keyId, spkiDER: der)
        case .rsaPssSha512:
            let pem = try String(contentsOf: Self.testdataPath.appendingPathComponent(v.pubKeyFile!), encoding: .utf8)
            let der = try PEMUtils.decodePEM(pem)
            return try RSAPSSVerifyingKey(keyId: v.keyId, spkiDER: der)
        case .ecdsaP256Sha256:
            let pem = try String(contentsOf: Self.testdataPath.appendingPathComponent(v.pubKeyFile!), encoding: .utf8)
            let der = try PEMUtils.decodePEM(pem)
            return try ECDSAP256VerifyingKey(keyId: v.keyId, derRepresentation: der)
        default:
            fatalError("No test vector key for algorithm \(v.algorithm)")
        }
    }

    // MARK: - Vector Loading

    static func loadAllVectors() -> [TestVector] {
        let fm = FileManager.default
        guard let files = try? fm.contentsOfDirectory(at: vectorsPath, includingPropertiesForKeys: nil)
            .filter({ $0.pathExtension == "json" })
            .sorted(by: { $0.lastPathComponent < $1.lastPathComponent })
        else {
            return []
        }
        return files.compactMap { file in
            guard let data = try? Data(contentsOf: file),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return nil }
            return parseVector(json)
        }
    }

    static func parseVector(_ json: [String: Any]) -> TestVector? {
        guard let id = json["id"] as? String,
              let description = json["description"] as? String,
              let messageJson = json["message"] as? [String: Any],
              let signingParams = json["signingParams"] as? [String: Any],
              let expectedBase = json["expectedBase"] as? String,
              let expectedSignatureInput = json["expectedSignatureInput"] as? String,
              let deterministic = json["deterministic"] as? Bool
        else { return nil }

        let message = parseMessage(messageJson)
        let requestMessage = (json["requestMessage"] as? [String: Any]).map { parseMessage($0) }

        let label = signingParams["label"] as? String ?? ""
        let keyId = signingParams["keyId"] as? String ?? ""
        let algorithm = signingParams["algorithm"] as? String ?? ""
        let created = signingParams["created"] as? Int64 ?? (signingParams["created"] as? Int).map { Int64($0) }
        let nonce = signingParams["nonce"] as? String
        let tag = signingParams["tag"] as? String

        var components: [ComponentIdentifier] = []
        if let comps = signingParams["components"] as? [Any] {
            for comp in comps {
                if let name = comp as? String {
                    components.append(ComponentIdentifier(name))
                } else if let obj = comp as? [String: Any],
                          let name = obj["name"] as? String,
                          let paramsDict = obj["params"] as? [String: Any] {
                    var sfvParams = SFVParams()
                    for (k, v) in paramsDict {
                        if let s = v as? String {
                            sfvParams.set(k, .string(s))
                        }
                    }
                    components.append(ComponentIdentifier(name, params: sfvParams))
                }
            }
        }

        return TestVector(
            id: id,
            description: description,
            message: message,
            requestMessage: requestMessage,
            label: label,
            keyId: keyId,
            algorithm: algorithm,
            components: components,
            created: created,
            nonce: nonce,
            tag: tag,
            expectedBase: expectedBase,
            expectedSignatureInput: expectedSignatureInput,
            expectedSignature: json["expectedSignature"] as? String,
            verifyOnlySignature: json["verifyOnlySignature"] as? String,
            deterministic: deterministic,
            keyFile: json["keyFile"] as? String,
            pubKeyFile: json["pubKeyFile"] as? String
        )
    }

    static func parseMessage(_ json: [String: Any]) -> MessageData {
        let type = json["type"] as? String ?? "request"
        let method = json["method"] as? String
        let url = json["url"] as? String
        let statusCode = json["statusCode"] as? Int
        var headers: [(String, String)] = []
        if let headerArray = json["headers"] as? [[Any]] {
            for pair in headerArray {
                if pair.count >= 2, let name = pair[0] as? String, let value = pair[1] as? String {
                    headers.append((name, value))
                }
            }
        }
        return MessageData(type: type, method: method, url: url, statusCode: statusCode, headers: headers)
    }
}
