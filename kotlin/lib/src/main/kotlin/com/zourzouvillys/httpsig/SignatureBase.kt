package com.zourzouvillys.httpsig

import java.nio.charset.StandardCharsets

/**
 * Constructs the signature base string per RFC 9421 Section 2.5.
 *
 * The signature base is a deterministic byte sequence derived from the
 * HTTP message, the covered components, and the signature parameters.
 * It's the input to the signing/verification algorithm.
 *
 *   "@method": GET
 *   "@authority": example.com
 *   "@signature-params": ("@method" "@authority");created=1618884473;keyid="test-key"
 */
internal object SignatureBase {

    data class Result(val base: ByteArray, val signatureInput: String)

    /**
     * Build the signature base for signing. The signature-input string
     * is computed from the parameters.
     */
    fun build(msg: HttpMessage, params: SignatureParameters, reqMsg: HttpMessage?): Result {
        validateNoDuplicates(params.components)
        val sigInput = buildSignatureInput(params)
        val base = buildBase(params.components, sigInput, msg, reqMsg)
        return Result(base, sigInput)
    }

    /**
     * Build the signature base for verification. The signature-input string
     * is the exact value from the Signature-Input header, preserving the
     * original parameter ordering.
     */
    fun buildForVerification(
        components: List<ComponentIdentifier>,
        signatureInput: String,
        msg: HttpMessage,
        reqMsg: HttpMessage?,
    ): ByteArray {
        validateNoDuplicates(components)
        return buildBase(components, signatureInput, msg, reqMsg)
    }

    private fun buildBase(
        components: List<ComponentIdentifier>,
        signatureInput: String,
        msg: HttpMessage,
        reqMsg: HttpMessage?,
    ): ByteArray {
        val sb = StringBuilder()
        for (cid in components) {
            val value = Components.extract(cid, msg, reqMsg)
            sb.append(SFV.serializeComponentId(cid))
            sb.append(": ")
            sb.append(value)
            sb.append('\n')
        }
        sb.append("\"@signature-params\": ")
        sb.append(signatureInput)
        return sb.toString().toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Build the signature-input value: the serialized inner list of components
     * followed by the signature metadata parameters.
     */
    fun buildSignatureInput(params: SignatureParameters): String {
        val sfvParams = buildSFVParams(params)
        return SFV.serializeSignatureParams(params.components, sfvParams)
    }

    /**
     * Build SFV params in canonical order: created, expires, keyid, alg, nonce, tag.
     */
    private fun buildSFVParams(params: SignatureParameters): SFV.Params {
        val map = linkedMapOf<String, Any?>()
        params.created?.let { map["created"] = it }
        params.expires?.let { map["expires"] = it }
        params.keyId?.let { map["keyid"] = it }
        params.algorithm?.let { map["alg"] = it.value }
        params.nonce?.let { map["nonce"] = it }
        params.tag?.let { map["tag"] = it }
        return SFV.Params(map)
    }

    private fun validateNoDuplicates(components: List<ComponentIdentifier>) {
        val seen = mutableSetOf<String>()
        for (cid in components) {
            val serialized = SFV.serializeComponentId(cid)
            if (!seen.add(serialized)) {
                throw HttpSigException("duplicate component in signature: $serialized")
            }
        }
    }
}
