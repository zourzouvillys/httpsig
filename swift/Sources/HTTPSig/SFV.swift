import Foundation

// MARK: - Value Types

/// An SFV Token (unquoted identifier).
public struct SFVToken: Sendable, Equatable, Hashable {
    public let value: String
    public init(_ value: String) { self.value = value }
}

/// A value in an SFV item. Using an enum because Swift's type system
/// is not "any Hashable" friendly and we need a closed set anyway.
public enum SFVValue: Sendable, Equatable, Hashable {
    case string(String)
    case int(Int64)
    case bool(Bool)
    case binary(Data)
    case token(SFVToken)
}

/// Ordered parameter map for SFV items/inner lists.
///
/// Parameters are ordered (insertion order matters for serialization)
/// and keyed by string with SFVValue values.
public struct SFVParams: Sendable, Equatable, Hashable {
    public private(set) var keys: [String] = []
    public private(set) var values: [String: SFVValue] = [:]

    public init() {}

    public var isEmpty: Bool { keys.isEmpty }
    public var count: Int { keys.count }

    public mutating func set(_ key: String, _ value: SFVValue) {
        if values[key] == nil {
            keys.append(key)
        }
        values[key] = value
    }

    public func get(_ key: String) -> SFVValue? {
        values[key]
    }

    public func has(_ key: String) -> Bool {
        values[key] != nil
    }

    public func getString(_ key: String) -> String? {
        if case .string(let s) = values[key] { return s }
        return nil
    }

    public func getInt(_ key: String) -> Int64? {
        if case .int(let n) = values[key] { return n }
        return nil
    }
}

/// An SFV Item: a bare value plus optional parameters.
public struct SFVItem: Sendable, Equatable {
    public let value: SFVValue
    public let params: SFVParams

    public init(value: SFVValue, params: SFVParams = SFVParams()) {
        self.value = value
        self.params = params
    }
}

/// An SFV Inner List: a list of items plus optional parameters.
public struct SFVInnerList: Sendable, Equatable {
    public let items: [SFVItem]
    public let params: SFVParams

    public init(items: [SFVItem], params: SFVParams = SFVParams()) {
        self.items = items
        self.params = params
    }
}

/// A member of an SFV Dictionary. Either an inner list or a single item.
public struct SFVDictMember: Sendable, Equatable {
    public let key: String
    public let innerList: SFVInnerList?
    public let item: SFVItem?

    public init(key: String, innerList: SFVInnerList) {
        self.key = key
        self.innerList = innerList
        self.item = nil
    }

    public init(key: String, item: SFVItem) {
        self.key = key
        self.innerList = nil
        self.item = item
    }
}

// MARK: - Serialization

public enum SFV {

    /// Serialize signature parameters for the @signature-params line.
    /// Format: ("@method" "@path");created=1618884473;keyid="test-key"
    public static func serializeSignatureParams(
        _ components: [ComponentIdentifier],
        _ params: SFVParams
    ) -> String {
        var result = "("
        for (i, c) in components.enumerated() {
            if i > 0 { result += " " }
            result += serializeComponentId(c)
        }
        result += ")"
        result += serializeParams(params)
        return result
    }

    /// Serialize a component identifier (name + params) for the inner list.
    public static func serializeComponentId(_ cid: ComponentIdentifier) -> String {
        var result = serializeString(cid.name)
        for key in cid.params.keys {
            guard let val = cid.params.values[key] else { continue }
            result += ";"
            result += key
            if case .bool(true) = val {
                continue
            }
            result += "="
            result += serializeBareItem(val)
        }
        return result
    }

    /// Serialize a bare item value per RFC 8941.
    public static func serializeBareItem(_ value: SFVValue) -> String {
        switch value {
        case .string(let s):
            return serializeString(s)
        case .int(let n):
            return String(n)
        case .bool(let b):
            return b ? "?1" : "?0"
        case .binary(let data):
            return ":" + data.base64EncodedString() + ":"
        case .token(let t):
            return t.value
        }
    }

    /// Serialize a full SFV Dictionary.
    public static func serializeDictionary(_ members: [SFVDictMember]) -> String {
        var parts: [String] = []
        for m in members {
            var s = m.key + "="
            if let il = m.innerList {
                s += serializeInnerList(il)
            } else if let item = m.item {
                s += serializeBareItem(item.value)
                if !item.params.isEmpty {
                    s += serializeParams(item.params)
                }
            }
            parts.append(s)
        }
        return parts.joined(separator: ", ")
    }

    /// Serialize an inner list.
    public static func serializeInnerList(_ il: SFVInnerList) -> String {
        var result = "("
        for (i, item) in il.items.enumerated() {
            if i > 0 { result += " " }
            result += serializeBareItem(item.value)
            if !item.params.isEmpty {
                result += serializeParams(item.params)
            }
        }
        result += ")"
        if !il.params.isEmpty {
            result += serializeParams(il.params)
        }
        return result
    }

    /// Serialize parameters.
    public static func serializeParams(_ params: SFVParams) -> String {
        guard !params.isEmpty else { return "" }
        var result = ""
        for key in params.keys {
            guard let val = params.values[key] else { continue }
            result += ";"
            result += key
            if case .bool(true) = val {
                continue
            }
            result += "="
            result += serializeBareItem(val)
        }
        return result
    }

    /// Serialize a string value with SFV quoting.
    static func serializeString(_ s: String) -> String {
        var result = "\""
        for ch in s {
            if ch == "\\" || ch == "\"" {
                result += "\\"
            }
            result += String(ch)
        }
        result += "\""
        return result
    }

    // MARK: - Parsing

    /// Parse an SFV Dictionary (RFC 8941 Section 3.2).
    public static func parseDictionary(_ input: String) throws -> [SFVDictMember] {
        var parser = SFVParser(input.trimmingCharacters(in: .whitespaces))
        var members: [SFVDictMember] = []

        while !parser.eof {
            let member = try parser.parseDictMember()
            members.append(member)

            parser.skipOWS()
            if parser.eof { break }

            guard let ch = parser.peek(), ch == Character(",") else {
                throw HttpSigError.sfvParseError("expected ',' at position \(parser.pos)")
            }
            parser.advance()
            parser.skipOWS()
            if parser.eof {
                throw HttpSigError.sfvParseError("trailing comma")
            }
        }

        return members
    }
}

// MARK: - Parser

struct SFVParser: ~Copyable {
    let input: [UInt8]
    var pos: Int

    init(_ string: String) {
        self.input = Array(string.utf8)
        self.pos = 0
    }

    var eof: Bool { pos >= input.count }

    func peek() -> Character? {
        guard pos < input.count else { return nil }
        return Character(UnicodeScalar(input[pos]))
    }

    func peekByte() -> UInt8? {
        guard pos < input.count else { return nil }
        return input[pos]
    }

    mutating func advance() {
        pos += 1
    }

    mutating func skipSP() {
        while pos < input.count && input[pos] == UInt8(ascii: " ") {
            pos += 1
        }
    }

    mutating func skipOWS() {
        while pos < input.count && (input[pos] == UInt8(ascii: " ") || input[pos] == UInt8(ascii: "\t")) {
            pos += 1
        }
    }

    // MARK: Dictionary

    mutating func parseDictMember() throws -> SFVDictMember {
        let key = try parseKey()

        guard let ch = peekByte(), ch == UInt8(ascii: "=") else {
            // bare member: boolean true with possible parameters
            let params = try parseParams()
            return SFVDictMember(
                key: key,
                item: SFVItem(value: .bool(true), params: params)
            )
        }
        advance() // skip '='

        if let ch = peekByte(), ch == UInt8(ascii: "(") {
            let il = try parseInnerList()
            return SFVDictMember(key: key, innerList: il)
        }

        let item = try parseItem()
        return SFVDictMember(key: key, item: item)
    }

    // MARK: Item

    mutating func parseItem() throws -> SFVItem {
        let value = try parseBareItem()
        let params = try parseParams()
        return SFVItem(value: value, params: params)
    }

    mutating func parseBareItem() throws -> SFVValue {
        guard let ch = peekByte() else {
            throw HttpSigError.sfvParseError("unexpected end of input")
        }
        switch ch {
        case UInt8(ascii: "\""):
            let s = try parseString()
            return .string(s)
        case UInt8(ascii: ":"):
            let data = try parseBinary()
            return .binary(data)
        case UInt8(ascii: "?"):
            let b = try parseBoolean()
            return .bool(b)
        case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
            let n = try parseNumber()
            return .int(n)
        case UInt8(ascii: "*"),
             UInt8(ascii: "a")...UInt8(ascii: "z"),
             UInt8(ascii: "A")...UInt8(ascii: "Z"):
            let t = try parseToken()
            return .token(t)
        default:
            throw HttpSigError.sfvParseError(
                "unexpected character '\(Character(UnicodeScalar(ch)))' at position \(pos)"
            )
        }
    }

    // MARK: String

    mutating func parseString() throws -> String {
        guard peekByte() == UInt8(ascii: "\"") else {
            throw HttpSigError.sfvParseError("expected '\"'")
        }
        advance()

        var result: [UInt8] = []
        while !eof {
            let ch = input[pos]
            if ch == UInt8(ascii: "\"") {
                advance()
                return String(bytes: result, encoding: .utf8)!
            }
            if ch == UInt8(ascii: "\\") {
                advance()
                guard !eof else {
                    throw HttpSigError.sfvParseError("unterminated escape in string")
                }
                let escaped = input[pos]
                guard escaped == UInt8(ascii: "\"") || escaped == UInt8(ascii: "\\") else {
                    throw HttpSigError.sfvParseError(
                        "invalid escape \\\(Character(UnicodeScalar(escaped)))"
                    )
                }
                result.append(escaped)
                advance()
                continue
            }
            guard ch >= 0x20 && ch <= 0x7e else {
                throw HttpSigError.sfvParseError("invalid character in string at position \(pos)")
            }
            result.append(ch)
            advance()
        }
        throw HttpSigError.sfvParseError("unterminated string")
    }

    // MARK: Binary

    mutating func parseBinary() throws -> Data {
        guard peekByte() == UInt8(ascii: ":") else {
            throw HttpSigError.sfvParseError("expected ':'")
        }
        advance()

        let start = pos
        while !eof && input[pos] != UInt8(ascii: ":") {
            pos += 1
        }
        guard !eof else {
            throw HttpSigError.sfvParseError("unterminated binary sequence")
        }
        let b64String = String(bytes: input[start..<pos], encoding: .utf8)!
        advance() // closing ':'

        guard let data = Data(base64Encoded: b64String) else {
            throw HttpSigError.sfvParseError("invalid base64 in binary")
        }
        return data
    }

    // MARK: Boolean

    mutating func parseBoolean() throws -> Bool {
        guard peekByte() == UInt8(ascii: "?") else {
            throw HttpSigError.sfvParseError("expected '?'")
        }
        advance()
        guard let ch = peekByte() else {
            throw HttpSigError.sfvParseError("expected '0' or '1'")
        }
        advance()
        switch ch {
        case UInt8(ascii: "1"): return true
        case UInt8(ascii: "0"): return false
        default:
            throw HttpSigError.sfvParseError(
                "expected '0' or '1', got '\(Character(UnicodeScalar(ch)))'"
            )
        }
    }

    // MARK: Number

    mutating func parseNumber() throws -> Int64 {
        let start = pos
        if peekByte() == UInt8(ascii: "-") {
            advance()
        }
        guard let ch = peekByte(), ch >= UInt8(ascii: "0") && ch <= UInt8(ascii: "9") else {
            throw HttpSigError.sfvParseError("invalid number at position \(start)")
        }
        while let ch = peekByte(), ch >= UInt8(ascii: "0") && ch <= UInt8(ascii: "9") {
            advance()
        }
        // reject decimals
        if peekByte() == UInt8(ascii: ".") {
            throw HttpSigError.sfvParseError("decimal numbers not supported in this subset")
        }
        let numStr = String(bytes: input[start..<pos], encoding: .utf8)!
        guard let n = Int64(numStr) else {
            throw HttpSigError.sfvParseError("number out of range: \(numStr)")
        }
        return n
    }

    // MARK: Token

    mutating func parseToken() throws -> SFVToken {
        let start = pos
        guard let ch = peekByte(), isAlpha(ch) || ch == UInt8(ascii: "*") else {
            throw HttpSigError.sfvParseError("invalid token start at position \(pos)")
        }
        advance()
        while let ch = peekByte(), isTokenChar(ch) {
            advance()
        }
        let value = String(bytes: input[start..<pos], encoding: .utf8)!
        return SFVToken(value)
    }

    // MARK: Parameters

    mutating func parseParams() throws -> SFVParams {
        var params = SFVParams()
        while let ch = peekByte(), ch == UInt8(ascii: ";") {
            advance() // consume ';'
            skipSP()
            let key = try parseKey()
            var value: SFVValue = .bool(true)
            if let ch = peekByte(), ch == UInt8(ascii: "=") {
                advance()
                value = try parseBareItem()
            }
            params.set(key, value)
        }
        return params
    }

    // MARK: Inner List

    mutating func parseInnerList() throws -> SFVInnerList {
        guard peekByte() == UInt8(ascii: "(") else {
            throw HttpSigError.sfvParseError("expected '(' at position \(pos)")
        }
        advance()

        var items: [SFVItem] = []
        while true {
            skipSP()
            guard let ch = peekByte() else {
                throw HttpSigError.sfvParseError("unterminated inner list")
            }
            if ch == UInt8(ascii: ")") {
                advance()
                break
            }
            let item = try parseItem()
            items.append(item)
        }

        let params = try parseParams()
        return SFVInnerList(items: items, params: params)
    }

    // MARK: Key

    mutating func parseKey() throws -> String {
        let start = pos
        guard let ch = peekByte(), isLcAlpha(ch) || ch == UInt8(ascii: "*") else {
            throw HttpSigError.sfvParseError("invalid key start at position \(pos)")
        }
        advance()
        while let ch = peekByte(), isKeyChar(ch) {
            advance()
        }
        return String(bytes: input[start..<pos], encoding: .utf8)!
    }

    // MARK: Character Classes

    func isAlpha(_ c: UInt8) -> Bool {
        (c >= UInt8(ascii: "a") && c <= UInt8(ascii: "z")) ||
        (c >= UInt8(ascii: "A") && c <= UInt8(ascii: "Z"))
    }

    func isLcAlpha(_ c: UInt8) -> Bool {
        c >= UInt8(ascii: "a") && c <= UInt8(ascii: "z")
    }

    func isDigit(_ c: UInt8) -> Bool {
        c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9")
    }

    func isTokenChar(_ c: UInt8) -> Bool {
        isAlpha(c) || isDigit(c) ||
        c == UInt8(ascii: "!") || c == UInt8(ascii: "#") ||
        c == UInt8(ascii: "$") || c == UInt8(ascii: "%") ||
        c == UInt8(ascii: "&") || c == UInt8(ascii: "'") ||
        c == UInt8(ascii: "*") || c == UInt8(ascii: "+") ||
        c == UInt8(ascii: "-") || c == UInt8(ascii: ".") ||
        c == UInt8(ascii: "^") || c == UInt8(ascii: "_") ||
        c == UInt8(ascii: "`") || c == UInt8(ascii: "|") ||
        c == UInt8(ascii: "~") || c == UInt8(ascii: ":") ||
        c == UInt8(ascii: "/")
    }

    func isKeyChar(_ c: UInt8) -> Bool {
        isLcAlpha(c) || isDigit(c) ||
        c == UInt8(ascii: "_") || c == UInt8(ascii: "-") ||
        c == UInt8(ascii: ".") || c == UInt8(ascii: "*")
    }
}
