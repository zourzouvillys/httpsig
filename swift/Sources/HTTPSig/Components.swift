import Foundation

/// Extracts component values from HTTP messages per RFC 9421 Section 2.
enum Components {

    /// Extract the value of a component from the message.
    ///
    /// - Parameters:
    ///   - cid: the component to extract
    ///   - msg: the HTTP message (request or response)
    ///   - reqMsg: the related request message (for ;req on responses, or nil)
    /// - Returns: the extracted string value
    static func extract(
        _ cid: ComponentIdentifier,
        from msg: some HttpMessage,
        reqMsg: (any HttpMessage)? = nil
    ) throws -> String {
        // ;req means extract from the request instead
        if cid.hasParam("req") {
            guard let reqMsg else {
                throw HttpSigError.missingComponent(";req used but no request message provided")
            }
            var strippedParams = SFVParams()
            for key in cid.params.keys where key != "req" {
                if let val = cid.params.get(key) {
                    strippedParams.set(key, val)
                }
            }
            let strippedCid = ComponentIdentifier(cid.name, params: strippedParams)
            return try extract(strippedCid, from: reqMsg, reqMsg: nil)
        }

        if cid.isDerived {
            return try extractDerived(cid, from: msg)
        }
        return try extractHeader(cid, from: msg)
    }

    // MARK: - Derived Components (Section 2.2)

    private static func extractDerived(
        _ cid: ComponentIdentifier,
        from msg: some HttpMessage
    ) throws -> String {
        switch cid.name {
        case "@method":
            try requireRequest(msg, "@method")
            return msg.method.uppercased()

        case "@target-uri":
            try requireRequest(msg, "@target-uri")
            return msg.url.absoluteString

        case "@authority":
            try requireRequest(msg, "@authority")
            return extractAuthority(msg.url)

        case "@scheme":
            try requireRequest(msg, "@scheme")
            return (msg.url.scheme ?? "").lowercased()

        case "@request-target":
            try requireRequest(msg, "@request-target")
            return extractRequestTarget(msg.url)

        case "@path":
            try requireRequest(msg, "@path")
            let path = msg.url.path
            return path.isEmpty ? "/" : path

        case "@query":
            try requireRequest(msg, "@query")
            return extractQuery(msg.url)

        case "@query-param":
            try requireRequest(msg, "@query-param")
            guard let paramName = cid.paramString("name") else {
                throw HttpSigError.missingComponent("@query-param requires ;name parameter")
            }
            return try extractQueryParam(msg.url, name: paramName)

        case "@status":
            if msg.isRequest {
                throw HttpSigError.missingComponent("@status only valid for response messages")
            }
            return String(msg.statusCode)

        default:
            throw HttpSigError.missingComponent("unknown derived component: \(cid.name)")
        }
    }

    // MARK: - Header Fields (Section 2.1)

    private static func extractHeader(
        _ cid: ComponentIdentifier,
        from msg: some HttpMessage
    ) throws -> String {
        let values = msg.headerValues(name: cid.name)

        if cid.hasParam("bs") {
            return try extractByteSequence(cid.name, values: values)
        }
        if cid.hasParam("sf") {
            return try extractStructuredField(cid.name, values: values)
        }
        if cid.hasParam("key") {
            return try extractDictKey(cid, values: values)
        }

        guard !values.isEmpty else {
            throw HttpSigError.missingComponent("header '\(cid.name)' not present in message")
        }
        return values.map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: ", ")
    }

    /// ;bs: Binary Sequence encoding.
    private static func extractByteSequence(
        _ name: String,
        values: [String]
    ) throws -> String {
        guard !values.isEmpty else {
            throw HttpSigError.missingComponent("header '\(name)' not present for ;bs")
        }
        return values.map { v in
            let trimmed = v.trimmingCharacters(in: .whitespaces)
            let b64 = Data(trimmed.utf8).base64EncodedString()
            return ":\(b64):"
        }.joined(separator: ", ")
    }

    /// ;sf: Structured field re-serialization.
    private static func extractStructuredField(
        _ name: String,
        values: [String]
    ) throws -> String {
        guard !values.isEmpty else {
            throw HttpSigError.missingComponent("header '\(name)' not present for ;sf")
        }
        return values.map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: ", ")
    }

    /// ;key: Dictionary member extraction.
    private static func extractDictKey(
        _ cid: ComponentIdentifier,
        values: [String]
    ) throws -> String {
        guard !values.isEmpty else {
            throw HttpSigError.missingComponent("header '\(cid.name)' not present for ;key")
        }
        guard let memberKey = cid.paramString("key") else {
            throw HttpSigError.missingComponent(";key parameter requires a string value")
        }
        let combined = values.map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: ", ")
        let members = try SFV.parseDictionary(combined)
        for member in members {
            if member.key == memberKey {
                if let il = member.innerList {
                    return SFV.serializeInnerList(il)
                }
                if let item = member.item {
                    var result = SFV.serializeBareItem(item.value)
                    if !item.params.isEmpty {
                        result += SFV.serializeParams(item.params)
                    }
                    return result
                }
            }
        }
        throw HttpSigError.missingComponent(
            ";key member '\(memberKey)' not found in header '\(cid.name)'"
        )
    }

    // MARK: - URI Helpers

    /// Extract authority from a URL, stripping default ports.
    static func extractAuthority(_ url: URL) -> String {
        let host = (url.host ?? "").lowercased()
        let port = url.port
        let scheme = (url.scheme ?? "").lowercased()

        if port == nil
            || (scheme == "http" && port == 80)
            || (scheme == "https" && port == 443) {
            return host
        }
        return "\(host):\(port!)"
    }

    /// Extract the request-target (path + optional query).
    private static func extractRequestTarget(_ url: URL) -> String {
        var path = url.path
        if path.isEmpty { path = "/" }
        if let query = url.query {
            return "\(path)?\(query)"
        }
        return path
    }

    /// Extract the query component with leading "?".
    private static func extractQuery(_ url: URL) -> String {
        if let query = url.query {
            return "?\(query)"
        }
        return "?"
    }

    /// Extract a specific query parameter value.
    private static func extractQueryParam(_ url: URL, name: String) throws -> String {
        guard let query = url.query else {
            throw HttpSigError.missingComponent("@query-param: no query string in URI")
        }
        let pairs = query.split(separator: "&", omittingEmptySubsequences: false)
        for pair in pairs {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            let decodedKey = String(parts[0]).removingPercentEncoding ?? String(parts[0])
            if decodedKey == name {
                if parts.count > 1 {
                    return String(parts[1]).removingPercentEncoding ?? String(parts[1])
                }
                return ""
            }
        }
        throw HttpSigError.missingComponent("@query-param: parameter '\(name)' not found")
    }

    private static func requireRequest(_ msg: some HttpMessage, _ component: String) throws {
        if !msg.isRequest {
            throw HttpSigError.missingComponent("\(component) only valid for request messages")
        }
    }
}
