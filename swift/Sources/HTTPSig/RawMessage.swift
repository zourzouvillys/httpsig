import Foundation

/// Simple HttpMessage implementation backed by plain fields.
/// Useful for testing and for wrapping raw HTTP data.
public struct RawMessage: HttpMessage {
    public let isRequest: Bool
    public let method: String
    public let url: URL
    public let statusCode: Int
    private let headers: [(String, String)]

    private init(
        isRequest: Bool,
        method: String,
        url: URL,
        statusCode: Int,
        headers: [(String, String)]
    ) {
        self.isRequest = isRequest
        self.method = method
        self.url = url
        self.statusCode = statusCode
        self.headers = headers
    }

    /// Create a request message.
    public static func request(
        method: String,
        url: URL,
        headers: [(String, String)] = []
    ) -> RawMessage {
        RawMessage(isRequest: true, method: method, url: url, statusCode: 0, headers: headers)
    }

    /// Create a response message.
    public static func response(
        statusCode: Int,
        headers: [(String, String)] = []
    ) -> RawMessage {
        // Responses don't have a meaningful URL or method, but the protocol requires them.
        RawMessage(
            isRequest: false,
            method: "",
            url: URL(string: "https://placeholder")!,
            statusCode: statusCode,
            headers: headers
        )
    }

    public func headerValues(name: String) -> [String] {
        let lower = name.lowercased()
        return headers
            .filter { $0.0.lowercased() == lower }
            .map { $0.1 }
    }
}
