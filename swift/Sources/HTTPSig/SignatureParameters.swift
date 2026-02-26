/// Parameters that control signature creation: which components to sign,
/// which algorithm/key to advertise, and optional metadata like created/expires.
public struct SignatureParameters: Sendable {
    public var components: [ComponentIdentifier]
    public var algorithm: Algorithm?
    public var keyId: String?
    public var created: Int64?
    public var expires: Int64?
    public var nonce: String?
    public var tag: String?

    public init(
        components: [ComponentIdentifier] = [],
        algorithm: Algorithm? = nil,
        keyId: String? = nil,
        created: Int64? = nil,
        expires: Int64? = nil,
        nonce: String? = nil,
        tag: String? = nil
    ) {
        self.components = components
        self.algorithm = algorithm
        self.keyId = keyId
        self.created = created
        self.expires = expires
        self.nonce = nonce
        self.tag = tag
    }
}
