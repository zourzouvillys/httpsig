import Foundation

/// A key that can produce signatures.
public protocol SigningKey: Sendable {
    var keyId: String { get }
    var algorithm: Algorithm { get }
    func sign(_ data: Data) throws -> Data
}
