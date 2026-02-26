/// Resolves a verifying key given a key ID and optional algorithm hint.
public protocol KeyProvider: Sendable {
    func resolve(keyId: String, algorithm: Algorithm?) throws -> (any VerifyingKey)?
}
