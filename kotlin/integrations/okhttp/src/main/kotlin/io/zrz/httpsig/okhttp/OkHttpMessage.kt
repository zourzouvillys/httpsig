package io.zrz.httpsig.okhttp

import io.zrz.httpsig.HttpMessage
import okhttp3.Request
import java.net.URI

/**
 * Adapts an OkHttp [Request] to the [HttpMessage] interface for signature operations.
 */
internal class OkHttpMessage(private val request: Request) : HttpMessage {

    override val isRequest: Boolean = true

    override val method: String = request.method

    override val url: URI = request.url.toUri()

    override val statusCode: Int = 0

    override fun headerValues(name: String): List<String> =
        request.headers(name)
}
