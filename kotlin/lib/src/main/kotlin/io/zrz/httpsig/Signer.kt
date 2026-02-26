package io.zrz.httpsig

import java.util.Base64

/**
 * Signs HTTP messages per RFC 9421.
 *
 * Usage:
 * ```
 *   val params = SignatureParameters.builder()
 *       .component("@method")
 *       .component("@authority")
 *       .component("content-type")
 *       .keyId("my-key")
 *       .created(Instant.now())
 *       .build()
 *
 *   val result = Signer.sign(request, "sig1", params, signingKey, null)
 *   // Add result headers to the outgoing message:
 *   //   Signature-Input: sig1=("@method" "@authority" "content-type");created=...;keyid="my-key"
 *   //   Signature: sig1=:base64signature:
 * ```
 */
object Signer {

    /**
     * The result of a signing operation.
     */
    data class SignResult(
        val label: String,
        val signatureInput: String,
        val signature: ByteArray,
    )

    /**
     * Sign an HTTP message.
     */
    fun sign(
        msg: HttpMessage,
        label: String,
        params: SignatureParameters,
        key: SigningKey,
        reqMsg: HttpMessage? = null,
    ): SignResult {
        val base = SignatureBase.build(msg, params, reqMsg)
        val sig = key.sign(base.base)
        return SignResult(label, base.signatureInput, sig)
    }

    /**
     * Combine multiple sign results into a single Signature-Input header value.
     */
    fun signatureInputHeader(vararg results: SignResult): String =
        results.joinToString(", ") { "${it.label}=${it.signatureInput}" }

    /**
     * Combine multiple sign results into a single Signature header value.
     */
    fun signatureHeader(vararg results: SignResult): String =
        results.joinToString(", ") {
            "${it.label}=:${Base64.getEncoder().encodeToString(it.signature)}:"
        }
}
