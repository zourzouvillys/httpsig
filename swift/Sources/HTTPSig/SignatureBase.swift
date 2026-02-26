import Foundation

/// Constructs the signature base string per RFC 9421 Section 2.5.
///
///   "@method": GET\n
///   "@authority": example.com\n
///   "@signature-params": ("@method" "@authority");created=1618884473;keyid="test-key"
///
/// Note: no trailing newline after @signature-params.
public enum SignatureBase {

    /// Result of building a signature base.
    public struct Result: Sendable {
        /// The raw signature base bytes (input to the signing algorithm).
        public let base: Data
        /// The signature-input value (the inner list + params string).
        public let signatureInput: String
    }

    /// Build the signature base for signing.
    /// The signature-input string is computed from the parameters.
    public static func build(
        msg: some HttpMessage,
        params: SignatureParameters,
        reqMsg: (any HttpMessage)? = nil
    ) throws -> Result {
        try validateNoDuplicates(params.components)
        let sigInput = buildSignatureInput(params)
        let base = try buildBase(params.components, signatureInput: sigInput, msg: msg, reqMsg: reqMsg)
        return Result(base: base, signatureInput: sigInput)
    }

    /// Build the signature base for verification.
    /// The signature-input string is the exact value from the Signature-Input header,
    /// preserving the original parameter ordering.
    public static func buildForVerification(
        components: [ComponentIdentifier],
        signatureInput: String,
        msg: some HttpMessage,
        reqMsg: (any HttpMessage)? = nil
    ) throws -> Data {
        try validateNoDuplicates(components)
        return try buildBase(components, signatureInput: signatureInput, msg: msg, reqMsg: reqMsg)
    }

    /// Build the signature-input value: the serialized inner list of components
    /// followed by the signature metadata parameters.
    public static func buildSignatureInput(_ params: SignatureParameters) -> String {
        let sfvParams = buildSFVParams(params)
        return SFV.serializeSignatureParams(params.components, sfvParams)
    }

    // MARK: - Private

    private static func buildBase(
        _ components: [ComponentIdentifier],
        signatureInput: String,
        msg: some HttpMessage,
        reqMsg: (any HttpMessage)?
    ) throws -> Data {
        var base = ""
        for cid in components {
            let value = try Components.extract(cid, from: msg, reqMsg: reqMsg)
            base += SFV.serializeComponentId(cid)
            base += ": "
            base += value
            base += "\n"
        }
        base += "\"@signature-params\": "
        base += signatureInput
        return Data(base.utf8)
    }

    /// Build SFV params in canonical order: created, expires, keyid, alg, nonce, tag.
    private static func buildSFVParams(_ params: SignatureParameters) -> SFVParams {
        var p = SFVParams()
        if let created = params.created {
            p.set("created", .int(created))
        }
        if let expires = params.expires {
            p.set("expires", .int(expires))
        }
        if let keyId = params.keyId {
            p.set("keyid", .string(keyId))
        }
        if let alg = params.algorithm {
            p.set("alg", .string(alg.rawValue))
        }
        if let nonce = params.nonce {
            p.set("nonce", .string(nonce))
        }
        if let tag = params.tag {
            p.set("tag", .string(tag))
        }
        return p
    }

    private static func validateNoDuplicates(_ components: [ComponentIdentifier]) throws {
        var seen = Set<String>()
        for cid in components {
            let serialized = SFV.serializeComponentId(cid)
            if seen.contains(serialized) {
                throw HttpSigError.duplicateComponent(serialized)
            }
            seen.insert(serialized)
        }
    }
}
