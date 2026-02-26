package com.zourzouvillys.httpsig

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * Extracts component values from HTTP messages per RFC 9421 Section 2.
 *
 * Handles both derived components (@method, @target-uri, etc.) and
 * header fields (plain, ;sf, ;bs, ;key).
 */
internal object Components {

    /**
     * Extract the value of a component from the message.
     */
    fun extract(cid: ComponentIdentifier, msg: HttpMessage, reqMsg: HttpMessage?): String {
        // ;req means extract from the request instead
        if (cid.hasParam("req")) {
            if (reqMsg == null) {
                throw HttpSigException(";req used but no request message provided")
            }
            val strippedParams = LinkedHashMap(cid.params).apply { remove("req") }
            val strippedCid = ComponentIdentifier.withParams(cid.name, strippedParams)
            return extract(strippedCid, reqMsg, null)
        }

        return if (cid.name.startsWith("@")) {
            extractDerived(cid.name, cid, msg)
        } else {
            extractHeader(cid.name, cid, msg)
        }
    }

    // ---- Derived components (Section 2.2) ----

    private fun extractDerived(name: String, cid: ComponentIdentifier, msg: HttpMessage): String =
        when (name) {
            "@method" -> {
                requireRequest(msg, name)
                msg.method!!.uppercase()
            }
            "@target-uri" -> {
                requireRequest(msg, name)
                msg.url!!.toASCIIString()
            }
            "@authority" -> {
                requireRequest(msg, name)
                extractAuthority(msg.url!!)
            }
            "@scheme" -> {
                requireRequest(msg, name)
                msg.url!!.scheme.lowercase()
            }
            "@request-target" -> {
                requireRequest(msg, name)
                extractRequestTarget(msg.url!!)
            }
            "@path" -> {
                requireRequest(msg, name)
                val path = msg.url!!.rawPath
                if (path.isNullOrEmpty()) "/" else path
            }
            "@query" -> {
                requireRequest(msg, name)
                val query = msg.url!!.rawQuery
                "?" + (query ?: "")
            }
            "@query-param" -> {
                requireRequest(msg, name)
                val paramName = cid.paramString("name")
                    ?: throw HttpSigException("@query-param requires ;name parameter")
                extractQueryParam(msg.url!!, paramName)
            }
            "@status" -> {
                if (msg.isRequest) {
                    throw HttpSigException("@status only valid for response messages")
                }
                msg.statusCode.toString()
            }
            else -> throw HttpSigException("unknown derived component: $name")
        }

    /**
     * Extract authority from a URI, stripping default ports (80 for http, 443 for https).
     */
    internal fun extractAuthority(uri: URI): String {
        val host = uri.host.lowercase()
        val port = uri.port
        val scheme = uri.scheme?.lowercase() ?: ""
        return if (port == -1 || (scheme == "http" && port == 80) || (scheme == "https" && port == 443)) {
            host
        } else {
            "$host:$port"
        }
    }

    private fun extractRequestTarget(uri: URI): String {
        val path = uri.rawPath.let { if (it.isNullOrEmpty()) "/" else it }
        val query = uri.rawQuery
        return if (query != null) "$path?$query" else path
    }

    private fun extractQueryParam(uri: URI, name: String): String {
        val query = uri.rawQuery
            ?: throw HttpSigException("@query-param: no query string in URI")

        val values = mutableListOf<String>()
        for (pair in query.split("&")) {
            val kv = pair.split("=", limit = 2)
            val decodedKey = URLDecoder.decode(kv[0], StandardCharsets.UTF_8)
            if (decodedKey == name) {
                values.add(
                    if (kv.size > 1) URLDecoder.decode(kv[1], StandardCharsets.UTF_8) else ""
                )
            }
        }

        if (values.isEmpty()) {
            throw HttpSigException("@query-param: parameter '$name' not found")
        }
        return values[0]
    }

    // ---- Header fields (Section 2.1) ----

    private fun extractHeader(name: String, cid: ComponentIdentifier, msg: HttpMessage): String {
        val values = msg.headerValues(name)

        if (cid.hasParam("bs")) {
            return extractByteSequence(name, values)
        }

        if (cid.hasParam("sf")) {
            return extractStructuredField(name, values)
        }

        if (cid.hasParam("key")) {
            return extractDictKey(name, cid, values)
        }

        // Plain header: concatenate multiple values with ", "
        if (values.isEmpty()) {
            throw HttpSigException("header '$name' not present in message")
        }
        return values.joinToString(", ") { it.trim() }
    }

    private fun extractByteSequence(name: String, values: List<String>): String {
        if (values.isEmpty()) {
            throw HttpSigException("header '$name' not present for ;bs")
        }
        return values.joinToString(", ") { v ->
            ":" + Base64.getEncoder().encodeToString(v.trim().toByteArray(StandardCharsets.UTF_8)) + ":"
        }
    }

    private fun extractStructuredField(name: String, values: List<String>): String {
        if (values.isEmpty()) {
            throw HttpSigException("header '$name' not present for ;sf")
        }
        return values.joinToString(", ") { it.trim() }
    }

    private fun extractDictKey(name: String, cid: ComponentIdentifier, values: List<String>): String {
        if (values.isEmpty()) {
            throw HttpSigException("header '$name' not present for ;key")
        }
        val key = cid.paramString("key")
            ?: throw HttpSigException(";key parameter requires a string value")

        val combined = values.joinToString(", ") { it.trim() }
        val members = SFV.parseDictionary(combined)

        for (member in members) {
            if (member.key == key) {
                return when (val v = member.value) {
                    is SFV.InnerList -> serializeInnerListForComponent(v)
                    is SFV.Item -> SFV.serializeBareItem(v.value) + serializeParams(v.params)
                    else -> SFV.serializeBareItem(v)
                }
            }
        }
        throw HttpSigException(";key member '$key' not found in header '$name'")
    }

    private fun serializeInnerListForComponent(il: SFV.InnerList): String =
        buildString {
            append('(')
            il.items.forEachIndexed { i, item ->
                if (i > 0) append(' ')
                append(SFV.serializeBareItem(item.value))
                append(serializeParams(item.params))
            }
            append(')')
            append(serializeParams(il.params))
        }

    private fun serializeParams(params: SFV.Params): String {
        if (params.isEmpty()) return ""
        return buildString {
            for ((key, value) in params.map) {
                append(';')
                append(key)
                if (value is Boolean) {
                    if (!value) append("=?0")
                } else {
                    append('=')
                    append(SFV.serializeBareItem(value))
                }
            }
        }
    }

    private fun requireRequest(msg: HttpMessage, component: String) {
        if (!msg.isRequest) {
            throw HttpSigException("$component only valid for request messages")
        }
    }
}
