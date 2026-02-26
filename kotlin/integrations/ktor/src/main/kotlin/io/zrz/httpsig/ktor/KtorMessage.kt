package io.zrz.httpsig.ktor

import io.zrz.httpsig.HttpMessage
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.http.URLBuilder
import java.net.URI

/**
 * Adapts a Ktor [HttpRequestBuilder] to the [HttpMessage] interface for signature operations.
 */
internal class KtorMessage(private val request: HttpRequestBuilder) : HttpMessage {

    override val isRequest: Boolean = true

    override val method: String = request.method.value

    override val url: URI = URI.create(URLBuilder(request.url).buildString())

    override val statusCode: Int = 0

    override fun headerValues(name: String): List<String> =
        request.headers.getAll(name) ?: emptyList()
}
