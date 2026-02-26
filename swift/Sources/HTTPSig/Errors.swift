/// Errors thrown by HTTP message signature operations.
public enum HttpSigError: Error, Sendable, Equatable {
    case unknownAlgorithm(String)
    case invalidKey(String)
    case invalidSignature(String)
    case missingComponent(String)
    case missingSignature
    case signatureExpired
    case keyNotFound(String)
    case malformedSignatureInput(String)
    case malformedSignature(String)
    case duplicateComponent(String)
    case sfvParseError(String)
}
