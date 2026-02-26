import Foundation
import CryptoKit

/// Content-Digest header support per RFC 9530.
public enum ContentDigest {

    /// Digest algorithm identifiers.
    public enum DigestAlgorithm: String, Sendable {
        case sha256 = "sha-256"
        case sha512 = "sha-512"
    }

    /// Compute a Content-Digest header value for the given body.
    ///
    /// - Returns: a complete header value, e.g. "sha-256=:base64digest:"
    public static func compute(body: Data, algorithm: DigestAlgorithm) -> String {
        let digest: Data
        switch algorithm {
        case .sha256:
            digest = Data(SHA256.hash(data: body))
        case .sha512:
            digest = Data(SHA512.hash(data: body))
        }
        return "\(algorithm.rawValue)=:\(digest.base64EncodedString()):"
    }

    /// Verify a Content-Digest header value against a body.
    ///
    /// The header value may contain multiple digest entries (SFV Dictionary).
    /// Returns true if at least one recognized algorithm matches.
    public static func verify(body: Data, headerValue: String) throws -> Bool {
        let entries = try SFV.parseDictionary(headerValue)
        var anyChecked = false

        for entry in entries {
            guard let alg = DigestAlgorithm(rawValue: entry.key) else {
                continue
            }
            anyChecked = true

            guard let item = entry.item, case .binary(let expectedDigest) = item.value else {
                throw HttpSigError.invalidSignature("invalid digest value for \(entry.key)")
            }

            let actual: Data
            switch alg {
            case .sha256:
                actual = Data(SHA256.hash(data: body))
            case .sha512:
                actual = Data(SHA512.hash(data: body))
            }

            // Constant-time comparison
            guard actual.count == expectedDigest.count else { return false }
            var diff: UInt8 = 0
            for (a, b) in zip(actual, expectedDigest) {
                diff |= a ^ b
            }
            if diff != 0 { return false }
        }

        if !anyChecked {
            throw HttpSigError.invalidSignature(
                "no recognized digest algorithm in Content-Digest header"
            )
        }
        return true
    }
}
