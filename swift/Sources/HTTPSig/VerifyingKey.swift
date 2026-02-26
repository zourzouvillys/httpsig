import Foundation

/// A key that can verify signatures.
public protocol VerifyingKey: Sendable {
    var keyId: String { get }
    var algorithm: Algorithm { get }
    func verify(_ data: Data, signature: Data) throws -> Bool
}
