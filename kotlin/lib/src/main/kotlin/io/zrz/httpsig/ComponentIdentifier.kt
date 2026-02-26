package io.zrz.httpsig

/**
 * Identifies a component to include in an HTTP message signature.
 *
 * Each component has a name (e.g. "@method", "content-type") and optional
 * ordered parameters (e.g. ;req, ;sf, ;key="member", ;name="qp").
 */
data class ComponentIdentifier(
    val name: String,
    val params: Map<String, Any> = emptyMap(),
) {
    init {
        require(name.isNotEmpty()) { "component name must not be empty" }
    }

    fun hasParam(key: String): Boolean = params.containsKey(key)

    fun paramString(key: String): String? = params[key] as? String

    companion object {
        /** Simple component with no params. */
        fun of(name: String): ComponentIdentifier = ComponentIdentifier(name)

        /** @query-param with ;name=<paramName>. */
        fun queryParam(paramName: String): ComponentIdentifier =
            ComponentIdentifier("@query-param", mapOf("name" to paramName))

        /** Wrap any component with the ;req flag for request-bound signatures. */
        fun req(name: String): ComponentIdentifier =
            ComponentIdentifier(name, mapOf("req" to true))

        /** Component with arbitrary params. */
        fun withParams(name: String, params: Map<String, Any>): ComponentIdentifier =
            ComponentIdentifier(name, LinkedHashMap(params))
    }
}
