import Foundation
import Testing
import HTTPSig
import HTTPSigAlamofire
import Alamofire

@Suite("SigningInterceptor")
struct SigningInterceptorTests {

    private static let secret = Data(base64Encoded:
        "uzvJfB4u3N0Jy4T7NZ75MDVcr8zSTInedJtkgcu46YW4XByzNJjxBdtjUkdJPBtbmHhIDi6pcl8jsasjlTMtDQ=="
    )!

    private static let key = HMACSHA256Key(keyId: "test-shared-secret", secret: secret)

    @Test("interceptor signs the request via adapt")
    func interceptorAdapt() async throws {
        let params = SignatureParameters(
            components: [
                ComponentIdentifier("@method"),
                ComponentIdentifier("@authority"),
            ],
            keyId: "test-shared-secret",
            created: 1618884473
        )

        let interceptor = SigningInterceptor(key: Self.key, label: "sig1", params: params)

        var request = URLRequest(url: URL(string: "https://example.com/test")!)
        request.httpMethod = "GET"

        let result: URLRequest = try await withCheckedThrowingContinuation { continuation in
            interceptor.adapt(request, for: Session.default) { result in
                continuation.resume(with: result)
            }
        }

        let sigInput = result.value(forHTTPHeaderField: "Signature-Input")
        let sig = result.value(forHTTPHeaderField: "Signature")

        #expect(sigInput != nil)
        #expect(sig != nil)
        #expect(sigInput!.contains("sig1="))
        #expect(sig!.hasPrefix("sig1=:"))
    }

    @Test("interceptor is Sendable")
    func sendable() {
        let params = SignatureParameters(
            components: [ComponentIdentifier("@method")],
            keyId: "test-shared-secret",
            created: 1618884473
        )
        let interceptor = SigningInterceptor(key: Self.key, label: "sig1", params: params)
        // This just needs to compile. If SigningInterceptor isn't Sendable, Swift 6 will reject it.
        let _: any Sendable = interceptor
    }
}
