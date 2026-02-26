import Foundation

/// Abstraction over an HTTP message (request or response) for signature operations.
public protocol HttpMessage: Sendable {
    /// True for requests, false for responses.
    var isRequest: Bool { get }

    /// HTTP method (uppercase). Only meaningful for requests.
    var method: String { get }

    /// Full request URL. Only meaningful for requests.
    var url: URL { get }

    /// Status code. Only meaningful for responses.
    var statusCode: Int { get }

    /// All values for the given header name (case-insensitive). Empty array if absent.
    func headerValues(name: String) -> [String]
}
