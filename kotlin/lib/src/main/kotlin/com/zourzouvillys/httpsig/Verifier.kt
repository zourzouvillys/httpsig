package com.zourzouvillys.httpsig

import java.time.Duration
import java.time.Instant
import java.util.function.Supplier

/**
 * Verifies HTTP message signatures per RFC 9421.
 *
 * Parses the Signature-Input and Signature headers, reconstructs the
 * signature base, and verifies using the key provided by a [KeyProvider].
 */
object Verifier {

    /**
     * Options controlling verification behavior.
     */
    data class VerifyOptions(
        val requiredComponents: List<ComponentIdentifier>? = null,
        val maxAge: Duration? = null,
        val maxClockSkew: Duration? = null,
        val rejectExpired: Boolean? = null,
        val requiredLabel: String? = null,
        val now: Supplier<Instant> = Supplier { Instant.now() },
    ) {
        companion object {
            fun defaults(): VerifyOptions = VerifyOptions()
        }
    }

    /**
     * The result of a successful verification.
     */
    data class VerifyResult(
        val label: String,
        val keyId: String?,
        val algorithm: Algorithm?,
        val components: List<ComponentIdentifier>,
        val created: Long?,
        val expires: Long?,
    )

    /**
     * Verify signatures on an HTTP message.
     *
     * @param msg      the message with Signature and Signature-Input headers
     * @param provider resolves verifying keys
     * @param options  verification options
     * @param reqMsg   the related request (for response signatures, or null)
     * @return the first successfully verified result
     * @throws HttpSigException if no signature verifies
     */
    fun verify(
        msg: HttpMessage,
        provider: KeyProvider,
        options: VerifyOptions = VerifyOptions.defaults(),
        reqMsg: HttpMessage? = null,
    ): VerifyResult {
        // parse Signature-Input header
        val sigInputHeaders = msg.headerValues("signature-input")
        if (sigInputHeaders.isEmpty()) {
            throw HttpSigException("no Signature-Input header found")
        }
        val sigInputCombined = sigInputHeaders.joinToString(", ")
        val sigInputEntries = SFV.parseDictionary(sigInputCombined)

        // parse Signature header
        val sigHeaders = msg.headerValues("signature")
        if (sigHeaders.isEmpty()) {
            throw HttpSigException("no Signature header found")
        }
        val sigCombined = sigHeaders.joinToString(", ")
        val sigEntries = SFV.parseDictionary(sigCombined)

        // index signatures by label
        val signatures = linkedMapOf<String, ByteArray>()
        for (entry in sigEntries) {
            val item = entry.value as? SFV.Item ?: continue
            val sigBytes = item.value as? ByteArray ?: continue
            signatures[entry.key] = sigBytes
        }

        // try each signature-input entry
        val errors = mutableListOf<String>()
        for (entry in sigInputEntries) {
            val label = entry.key

            // if a specific label is required, skip others
            if (options.requiredLabel != null && options.requiredLabel != label) {
                continue
            }

            try {
                return verifySingle(label, entry, signatures, msg, provider, options, reqMsg)
            } catch (e: HttpSigException) {
                errors.add("$label: ${e.message}")
            }
        }

        throw HttpSigException("no signature verified: ${errors.joinToString("; ")}")
    }

    private fun verifySingle(
        label: String,
        sigInputEntry: SFV.DictMember,
        signatures: Map<String, ByteArray>,
        msg: HttpMessage,
        provider: KeyProvider,
        options: VerifyOptions,
        reqMsg: HttpMessage?,
    ): VerifyResult {
        val sigBytes = signatures[label]
            ?: throw HttpSigException("no matching Signature entry for label '$label'")

        val innerList = sigInputEntry.value as? SFV.InnerList
            ?: throw HttpSigException("signature-input for '$label' is not an inner list")

        // extract components from the inner list
        val components = innerList.items.map { item ->
            val name = item.value as? String
                ?: throw HttpSigException("component identifier must be a string")
            ComponentIdentifier.withParams(name, LinkedHashMap<String, Any>(item.params.map.mapValues { it.value as Any }))
        }

        // extract signature metadata from the inner list's params
        val metaParams = innerList.params
        val created = toLong(metaParams["created"])
        val expires = toLong(metaParams["expires"])
        val keyId = metaParams["keyid"] as? String
        val algStr = metaParams["alg"] as? String
        val algorithm = algStr?.let { Algorithm.fromValue(it) }

        // check required components
        options.requiredComponents?.let { required ->
            for (req in required) {
                val reqSer = SFV.serializeComponentId(req)
                val found = components.any { SFV.serializeComponentId(it) == reqSer }
                if (!found) {
                    throw HttpSigException("required component $reqSer not covered")
                }
            }
        }

        // check age/expiry
        val now = options.now.get()
        if (options.maxAge != null && created != null) {
            val createdTime = Instant.ofEpochSecond(created)
            if (now.isAfter(createdTime.plus(options.maxAge))) {
                throw HttpSigException("signature too old")
            }
        }
        if (options.maxClockSkew != null && created != null) {
            val createdTime = Instant.ofEpochSecond(created)
            if (createdTime.isAfter(now.plus(options.maxClockSkew))) {
                throw HttpSigException("signature future-dated")
            }
        }
        if (options.rejectExpired == true && expires != null) {
            if (now.isAfter(Instant.ofEpochSecond(expires))) {
                throw HttpSigException("signature expired")
            }
        }

        // resolve key
        val key = provider.resolve(keyId, algorithm)
            ?: throw HttpSigException("no key found for keyId='$keyId'")

        // if algorithm was specified in the input, it must match the key
        if (algorithm != null && key.algorithm != algorithm) {
            throw HttpSigException(
                "algorithm mismatch: input says $algorithm but key uses ${key.algorithm}"
            )
        }

        // re-serialize the inner list to get the exact signature-input value.
        // this preserves the original parameter ordering from the header.
        val signatureInput = SFV.serializeInnerList(innerList)
        val base = SignatureBase.buildForVerification(components, signatureInput, msg, reqMsg)

        // verify
        if (!key.verify(base, sigBytes)) {
            throw HttpSigException("signature verification failed for label '$label'")
        }

        return VerifyResult(
            label = label,
            keyId = key.keyId,
            algorithm = key.algorithm,
            components = components.toList(),
            created = created,
            expires = expires,
        )
    }

    private fun toLong(v: Any?): Long? = when (v) {
        is Long -> v
        is Int -> v.toLong()
        else -> null
    }
}
