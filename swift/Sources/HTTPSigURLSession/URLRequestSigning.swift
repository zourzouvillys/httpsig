import Foundation
import HTTPSig

// MARK: - URLRequest signing

extension URLRequest {

    /// Sign this request and return a new URLRequest with Signature-Input and Signature headers added.
    public func signed(
        label: String,
        params: SignatureParameters,
        key: some SigningKey
    ) throws -> URLRequest {
        let msg = URLRequestMessage(self)
        let result = try Signer.sign(msg: msg, label: label, params: params, key: key)
        var signed = self
        signed.addValue(Signer.signatureInputHeader(result), forHTTPHeaderField: "Signature-Input")
        signed.addValue(Signer.signatureHeader(result), forHTTPHeaderField: "Signature")
        return signed
    }
}

// MARK: - URLRequest as HttpMessage

struct URLRequestMessage: HttpMessage {
    let isRequest = true
    let method: String
    let url: URL
    let statusCode = 0
    private let request: URLRequest

    init(_ request: URLRequest) {
        self.request = request
        self.method = request.httpMethod?.uppercased() ?? "GET"
        self.url = request.url ?? URL(string: "https://localhost")!
    }

    func headerValues(name: String) -> [String] {
        guard let value = request.value(forHTTPHeaderField: name) else { return [] }
        return [value]
    }
}

// MARK: - HTTPURLResponse as HttpMessage

/// Wraps an HTTPURLResponse (and optionally a request URL) into an HttpMessage for verification.
public struct URLResponseMessage: HttpMessage {
    public let isRequest = false
    public let method = ""
    public let url: URL
    public let statusCode: Int
    private let response: HTTPURLResponse

    public init(_ response: HTTPURLResponse) {
        self.response = response
        self.statusCode = response.statusCode
        self.url = response.url ?? URL(string: "https://localhost")!
    }

    public func headerValues(name: String) -> [String] {
        guard let value = response.value(forHTTPHeaderField: name) else { return [] }
        return [value]
    }
}
