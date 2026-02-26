import Foundation
import Alamofire
import HTTPSig
import HTTPSigURLSession

/// Alamofire RequestInterceptor that signs outgoing requests with HTTP Message Signatures (RFC 9421).
public struct SigningInterceptor: RequestInterceptor, Sendable {
    private let key: any SigningKey
    private let label: String
    private let params: SignatureParameters

    public init(key: some SigningKey, label: String, params: SignatureParameters) {
        self.key = key
        self.label = label
        self.params = params
    }

    public func adapt(
        _ urlRequest: URLRequest,
        for session: Session,
        completion: @escaping (Result<URLRequest, any Error>) -> Void
    ) {
        do {
            let signed = try urlRequest.signed(label: label, params: params, key: key)
            completion(.success(signed))
        } catch {
            completion(.failure(error))
        }
    }
}
