import Foundation

/// The result of a signing operation.
public struct SignResult: Sendable {
    /// The signature label (e.g. "sig1").
    public let label: String
    /// The Signature-Input value for this label (the inner list + params).
    public let signatureInput: String
    /// The raw signature bytes.
    public let signature: Data

    public init(label: String, signatureInput: String, signature: Data) {
        self.label = label
        self.signatureInput = signatureInput
        self.signature = signature
    }
}

/// Signs HTTP messages per RFC 9421.
public enum Signer {

    /// Sign an HTTP message.
    ///
    /// - Parameters:
    ///   - msg: the message to sign
    ///   - label: the signature label (e.g. "sig1")
    ///   - params: what to sign and with what metadata
    ///   - key: the signing key
    ///   - reqMsg: the related request (for response signatures, or nil)
    /// - Returns: the signing result
    public static func sign(
        msg: some HttpMessage,
        label: String,
        params: SignatureParameters,
        key: some SigningKey,
        reqMsg: (any HttpMessage)? = nil
    ) throws -> SignResult {
        let baseResult = try SignatureBase.build(msg: msg, params: params, reqMsg: reqMsg)
        let sig = try key.sign(baseResult.base)
        return SignResult(label: label, signatureInput: baseResult.signatureInput, signature: sig)
    }

    /// Combine multiple sign results into a single Signature-Input header value.
    public static func signatureInputHeader(_ results: SignResult...) -> String {
        signatureInputHeader(results)
    }

    /// Combine multiple sign results into a single Signature-Input header value.
    public static func signatureInputHeader(_ results: [SignResult]) -> String {
        results.map { "\($0.label)=\($0.signatureInput)" }.joined(separator: ", ")
    }

    /// Combine multiple sign results into a single Signature header value.
    public static func signatureHeader(_ results: SignResult...) -> String {
        signatureHeader(results)
    }

    /// Combine multiple sign results into a single Signature header value.
    public static func signatureHeader(_ results: [SignResult]) -> String {
        results.map { "\($0.label)=:\($0.signature.base64EncodedString()):" }.joined(separator: ", ")
    }
}
