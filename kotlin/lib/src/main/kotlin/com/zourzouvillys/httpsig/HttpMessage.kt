package com.zourzouvillys.httpsig

import java.net.URI

/**
 * Abstraction over an HTTP message (request or response) for signature operations.
 *
 * Implementations wrap whatever HTTP library the caller is using.
 */
interface HttpMessage {

    /** True for requests, false for responses. */
    val isRequest: Boolean

    /** HTTP method (uppercase). Only meaningful for requests. */
    val method: String?

    /** Full request URI. Only meaningful for requests. */
    val url: URI?

    /** Status code. Only meaningful for responses. */
    val statusCode: Int

    /** All values for the given header name (case-insensitive). Empty list if absent. */
    fun headerValues(name: String): List<String>
}
