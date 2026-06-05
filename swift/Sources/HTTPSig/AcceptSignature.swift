import Foundation

/// Defines what a valid signature must contain.
/// Used for both verification filtering and Accept-Signature negotiation (RFC 9421 Section 5).
public struct SignatureRequirements: Sendable, Equatable {
    /// Required components that must be covered by the signature.
    public var components: [ComponentIdentifier]
    /// Expected key identifier. Nil means any key.
    public var keyId: String?
    /// Expected algorithm. Nil means any algorithm.
    public var algorithm: Algorithm?
    /// Expected tag. Nil means any tag.
    public var tag: String?
    /// If true, the signature must have a ;created parameter.
    public var requireCreated: Bool
    /// If true, the signature must have an ;expires parameter.
    public var requireExpires: Bool

    public init(
        components: [ComponentIdentifier] = [],
        keyId: String? = nil,
        algorithm: Algorithm? = nil,
        tag: String? = nil,
        requireCreated: Bool = false,
        requireExpires: Bool = false
    ) {
        self.components = components
        self.keyId = keyId
        self.algorithm = algorithm
        self.tag = tag
        self.requireCreated = requireCreated
        self.requireExpires = requireExpires
    }

    /// Convert requirements to SignatureParameters for signing a matching request.
    public func signatureParameters(
        created: Int64? = nil,
        expires: Int64? = nil,
        nonce: String? = nil
    ) -> SignatureParameters {
        SignatureParameters(
            components: components,
            algorithm: algorithm,
            keyId: keyId,
            created: created,
            expires: expires,
            nonce: nonce,
            tag: tag
        )
    }
}

/// Accept-Signature header construction and parsing per RFC 9421 Section 5.
public enum AcceptSignature {

    /// Build an Accept-Signature header value from labeled requirements.
    ///
    /// Each entry becomes a dictionary member whose value is an inner list of
    /// component identifiers with params for keyid, alg, tag, created, and expires.
    public static func build(_ entries: [String: SignatureRequirements]) -> String {
        // Sort keys for deterministic output
        let sortedKeys = entries.keys.sorted()
        var members: [SFVDictMember] = []
        for key in sortedKeys {
            guard let req = entries[key] else { continue }
            members.append(buildMember(key: key, req: req))
        }
        return SFV.serializeDictionary(members)
    }

    /// Parse an Accept-Signature header value into labeled requirements.
    public static func parse(_ headerValue: String) throws -> [String: SignatureRequirements] {
        let members = try SFV.parseDictionary(headerValue)
        var result: [String: SignatureRequirements] = [:]
        for member in members {
            result[member.key] = try parseMember(member)
        }
        return result
    }

    // MARK: - Private

    private static func buildMember(key: String, req: SignatureRequirements) -> SFVDictMember {
        // Build inner list items from components
        let items: [SFVItem] = req.components.map { cid in
            SFVItem(value: .string(cid.name), params: cid.params)
        }

        // Build inner list params
        var params = SFVParams()
        if let keyId = req.keyId {
            params.set("keyid", .string(keyId))
        }
        if let alg = req.algorithm {
            params.set("alg", .string(alg.rawValue))
        }
        if let tag = req.tag {
            params.set("tag", .string(tag))
        }
        if req.requireCreated {
            params.set("created", .bool(true))
        }
        if req.requireExpires {
            params.set("expires", .bool(true))
        }

        let innerList = SFVInnerList(items: items, params: params)
        return SFVDictMember(key: key, innerList: innerList)
    }

    private static func parseMember(_ member: SFVDictMember) throws -> SignatureRequirements {
        guard let innerList = member.innerList else {
            throw HttpSigError.sfvParseError(
                "Accept-Signature member '\(member.key)' must be an inner list"
            )
        }

        // Extract components from inner list items
        var components: [ComponentIdentifier] = []
        for item in innerList.items {
            guard case .string(let name) = item.value else {
                throw HttpSigError.sfvParseError(
                    "Accept-Signature component identifier must be a string"
                )
            }
            components.append(ComponentIdentifier(name, params: item.params))
        }

        // Extract params
        let params = innerList.params
        let keyId = params.getString("keyid")
        let algStr = params.getString("alg")
        let algorithm = algStr.flatMap { Algorithm(rawValue: $0) }
        let tag = params.getString("tag")
        let requireCreated = params.has("created")
        let requireExpires = params.has("expires")

        return SignatureRequirements(
            components: components,
            keyId: keyId,
            algorithm: algorithm,
            tag: tag,
            requireCreated: requireCreated,
            requireExpires: requireExpires
        )
    }
}
