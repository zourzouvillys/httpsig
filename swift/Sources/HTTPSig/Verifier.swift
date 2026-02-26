import Foundation

/// Options controlling verification behavior.
public struct VerifyOptions: Sendable {
    /// Components that must be covered by the signature.
    public var requiredComponents: [ComponentIdentifier]?

    /// Reject signatures older than this (based on created). Nil means no age check.
    public var maxAge: TimeInterval?

    /// If true, reject signatures past their expires time. Defaults to true.
    public var rejectExpired: Bool

    /// If set, only verify the signature with this specific label.
    public var requiredLabel: String?

    /// Clock source for age/expiry checks. Defaults to Date().
    public var now: @Sendable () -> Date

    public init(
        requiredComponents: [ComponentIdentifier]? = nil,
        maxAge: TimeInterval? = nil,
        rejectExpired: Bool = true,
        requiredLabel: String? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.requiredComponents = requiredComponents
        self.maxAge = maxAge
        self.rejectExpired = rejectExpired
        self.requiredLabel = requiredLabel
        self.now = now
    }
}

/// The result of a successful verification.
public struct VerifyResult: Sendable {
    public let label: String
    public let keyId: String
    public let algorithm: Algorithm
    public let components: [ComponentIdentifier]
    public let created: Int64?
    public let expires: Int64?
}

/// Verifies HTTP message signatures per RFC 9421.
public enum Verifier {

    /// Verify signatures on an HTTP message.
    ///
    /// Parses the Signature-Input and Signature headers, reconstructs the
    /// signature base, and verifies using the key from the provider.
    ///
    /// - Parameters:
    ///   - msg: the message with Signature and Signature-Input headers
    ///   - provider: resolves verifying keys
    ///   - options: verification options
    ///   - reqMsg: the related request (for response signatures, or nil)
    /// - Returns: the first successfully verified result
    public static func verify(
        msg: some HttpMessage,
        provider: some KeyProvider,
        options: VerifyOptions = VerifyOptions(),
        reqMsg: (any HttpMessage)? = nil
    ) throws -> VerifyResult {
        // Parse Signature-Input header
        let sigInputHeaders = msg.headerValues(name: "signature-input")
        guard !sigInputHeaders.isEmpty else {
            throw HttpSigError.missingSignature
        }
        let sigInputCombined = sigInputHeaders.joined(separator: ", ")
        let sigInputEntries: [SFVDictMember]
        do {
            sigInputEntries = try SFV.parseDictionary(sigInputCombined)
        } catch {
            throw HttpSigError.malformedSignatureInput("\(error)")
        }

        // Parse Signature header
        let sigHeaders = msg.headerValues(name: "signature")
        guard !sigHeaders.isEmpty else {
            throw HttpSigError.missingSignature
        }
        let sigCombined = sigHeaders.joined(separator: ", ")
        let sigEntries: [SFVDictMember]
        do {
            sigEntries = try SFV.parseDictionary(sigCombined)
        } catch {
            throw HttpSigError.malformedSignature("\(error)")
        }

        // Index signatures by label
        var signatures: [String: Data] = [:]
        for entry in sigEntries {
            if let item = entry.item, case .binary(let data) = item.value {
                signatures[entry.key] = data
            }
        }

        // Try each signature-input entry
        var errors: [String] = []
        for entry in sigInputEntries {
            let label = entry.key

            // If a specific label is required, skip others
            if let requiredLabel = options.requiredLabel, label != requiredLabel {
                continue
            }

            do {
                let result = try verifySingle(
                    label: label,
                    sigInputEntry: entry,
                    signatures: signatures,
                    msg: msg,
                    provider: provider,
                    options: options,
                    reqMsg: reqMsg
                )
                return result
            } catch {
                errors.append("\(label): \(error)")
            }
        }

        throw HttpSigError.invalidSignature("no signature verified: \(errors.joined(separator: "; "))")
    }

    private static func verifySingle(
        label: String,
        sigInputEntry: SFVDictMember,
        signatures: [String: Data],
        msg: some HttpMessage,
        provider: some KeyProvider,
        options: VerifyOptions,
        reqMsg: (any HttpMessage)?
    ) throws -> VerifyResult {
        guard let sigBytes = signatures[label] else {
            throw HttpSigError.invalidSignature("no matching Signature entry for label '\(label)'")
        }

        guard let innerList = sigInputEntry.innerList else {
            throw HttpSigError.malformedSignatureInput(
                "signature-input for '\(label)' is not an inner list"
            )
        }

        // Extract components from the inner list
        var components: [ComponentIdentifier] = []
        for item in innerList.items {
            guard case .string(let name) = item.value else {
                throw HttpSigError.malformedSignatureInput("component identifier must be a string")
            }
            components.append(ComponentIdentifier(name, params: item.params))
        }

        // Extract signature metadata from the inner list's params
        let metaParams = innerList.params

        let created: Int64? = metaParams.getInt("created")
        let expires: Int64? = metaParams.getInt("expires")
        let keyId: String? = metaParams.getString("keyid")
        let algStr: String? = metaParams.getString("alg")
        let algorithm: Algorithm? = algStr.flatMap { Algorithm(rawValue: $0) }

        // Check required components
        if let required = options.requiredComponents, !required.isEmpty {
            let haveSet = Set(components.map { SFV.serializeComponentId($0) })
            for req in required {
                let reqSer = SFV.serializeComponentId(req)
                if !haveSet.contains(reqSer) {
                    throw HttpSigError.invalidSignature(
                        "required component \(reqSer) not covered"
                    )
                }
            }
        }

        // Check age/expiry
        let now = options.now()
        if let maxAge = options.maxAge, let created {
            let createdDate = Date(timeIntervalSince1970: TimeInterval(created))
            if now.timeIntervalSince(createdDate) > maxAge {
                throw HttpSigError.signatureExpired
            }
        }
        if options.rejectExpired, let expires {
            let expiresDate = Date(timeIntervalSince1970: TimeInterval(expires))
            if now > expiresDate {
                throw HttpSigError.signatureExpired
            }
        }

        // Resolve key
        guard let key = try provider.resolve(keyId: keyId ?? "", algorithm: algorithm) else {
            throw HttpSigError.keyNotFound("no key found for keyId='\(keyId ?? "")'")
        }

        // If algorithm was specified in the input, it must match the key
        if let algorithm, key.algorithm != algorithm {
            throw HttpSigError.invalidSignature(
                "algorithm mismatch: input says \(algorithm) but key uses \(key.algorithm)"
            )
        }

        // Re-serialize the inner list to get the exact signature-input value.
        // This preserves the original parameter ordering from the header.
        let signatureInput = SFV.serializeInnerList(innerList)
        let base = try SignatureBase.buildForVerification(
            components: components,
            signatureInput: signatureInput,
            msg: msg,
            reqMsg: reqMsg
        )

        // Verify
        guard try key.verify(base, signature: sigBytes) else {
            throw HttpSigError.invalidSignature(
                "signature verification failed for label '\(label)'"
            )
        }

        return VerifyResult(
            label: label,
            keyId: key.keyId,
            algorithm: key.algorithm,
            components: components,
            created: created,
            expires: expires
        )
    }
}
