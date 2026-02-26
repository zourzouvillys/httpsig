package com.zourzouvillys.httpsig.ktor

import com.zourzouvillys.httpsig.SignatureParameters
import com.zourzouvillys.httpsig.Signer
import com.zourzouvillys.httpsig.SigningKey
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.request.HttpRequestBuilder

/**
 * Configuration for the [HttpSig] client plugin.
 */
class HttpSigConfig {
    /** The signing key to use for all requests. */
    lateinit var key: SigningKey

    /** The signature label (defaults to "sig1"). */
    var label: String = "sig1"

    /**
     * Factory that builds [SignatureParameters] for each outgoing request.
     * Called once per request, receiving the [HttpRequestBuilder] so callers
     * can vary components or metadata per-request.
     */
    var paramsFactory: (HttpRequestBuilder) -> SignatureParameters = {
        throw IllegalStateException("paramsFactory must be configured")
    }
}

/**
 * Ktor client plugin that signs outgoing requests per RFC 9421.
 *
 * Adds `Signature-Input` and `Signature` headers to every request.
 *
 * Usage:
 * ```
 * val client = HttpClient(CIO) {
 *     install(HttpSig) {
 *         key = mySigningKey
 *         label = "sig1"
 *         paramsFactory = { request ->
 *             SignatureParameters.builder()
 *                 .component("@method")
 *                 .component("@authority")
 *                 .keyId("my-key")
 *                 .build()
 *         }
 *     }
 * }
 * ```
 */
val HttpSig = createClientPlugin("HttpSig", ::HttpSigConfig) {
    val key = pluginConfig.key
    val label = pluginConfig.label
    val paramsFactory = pluginConfig.paramsFactory

    onRequest { request, _ ->
        val msg = KtorMessage(request)
        val params = paramsFactory(request)
        val result = Signer.sign(msg, label, params, key)

        request.headers.append("Signature-Input", Signer.signatureInputHeader(result))
        request.headers.append("Signature", Signer.signatureHeader(result))
    }
}
