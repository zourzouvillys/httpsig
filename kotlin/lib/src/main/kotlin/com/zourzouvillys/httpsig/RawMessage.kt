package com.zourzouvillys.httpsig

import java.net.URI
import java.util.TreeMap

/**
 * Simple [HttpMessage] implementation backed by plain fields.
 * Useful for testing and for wrapping raw HTTP data.
 */
sealed class RawMessage private constructor(
    override val isRequest: Boolean,
    override val method: String?,
    override val url: URI?,
    override val statusCode: Int,
    headers: Map<String, List<String>>?,
) : HttpMessage {

    private val headers: Map<String, List<String>> =
        TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER).apply {
            headers?.forEach { (k, v) -> put(k, v.toList()) }
        }

    override fun headerValues(name: String): List<String> =
        headers.getOrDefault(name, emptyList())

    class Request(
        method: String,
        url: URI,
        headers: Map<String, List<String>>? = null,
    ) : RawMessage(true, method, url, 0, headers)

    class Response(
        statusCode: Int,
        headers: Map<String, List<String>>? = null,
    ) : RawMessage(false, null, null, statusCode, headers)

    companion object {
        fun request(method: String, url: URI, headers: Map<String, List<String>>? = null): Request =
            Request(method, url, headers)

        fun response(statusCode: Int, headers: Map<String, List<String>>? = null): Response =
            Response(statusCode, headers)
    }
}
