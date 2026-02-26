/// Identifies a component to include in an HTTP message signature.
///
/// Each component has a name (e.g. "@method", "content-type") and optional
/// ordered parameters (e.g. ;req, ;sf, ;key="member", ;name="qp").
public struct ComponentIdentifier: Sendable, Equatable, Hashable {
    public let name: String
    public let params: SFVParams

    public init(_ name: String) {
        self.name = name.lowercased()
        self.params = SFVParams()
    }

    public init(_ name: String, params: SFVParams) {
        self.name = name.lowercased()
        self.params = params
    }

    /// @query-param with ;name=<paramName>.
    public static func queryParam(_ paramName: String) -> ComponentIdentifier {
        var p = SFVParams()
        p.set("name", .string(paramName))
        return ComponentIdentifier("@query-param", params: p)
    }

    /// Wrap any component with the ;req flag for request-bound response signatures.
    public static func req(_ name: String) -> ComponentIdentifier {
        var p = SFVParams()
        p.set("req", .bool(true))
        return ComponentIdentifier(name, params: p)
    }

    /// Whether this is a derived component (starts with @).
    var isDerived: Bool {
        name.hasPrefix("@")
    }

    /// Whether a parameter is set.
    func hasParam(_ key: String) -> Bool {
        params.has(key)
    }

    /// Get a string parameter value.
    func paramString(_ key: String) -> String? {
        params.getString(key)
    }
}
