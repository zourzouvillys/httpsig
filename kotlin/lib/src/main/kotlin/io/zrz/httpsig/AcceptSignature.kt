package io.zrz.httpsig

/**
 * Describes what a valid signature must look like.
 *
 * Used for:
 * - Verification filtering: the verifier uses it to decide if a signature is acceptable
 * - Accept-Signature building: serializes to an Accept-Signature header entry
 * - SignatureParameters conversion: converts to params for signing a matching request
 */
data class SignatureRequirements(
    val components: List<ComponentIdentifier> = emptyList(),
    val keyId: String? = null,
    val algorithm: Algorithm? = null,
    val tag: String? = null,
    val requireCreated: Boolean = false,
    val requireExpires: Boolean = false,
) {
    /**
     * Convert these requirements to [SignatureParameters] suitable for signing.
     *
     * @param created epoch seconds for the created timestamp (or null to omit)
     * @param expires epoch seconds for the expires timestamp (or null to omit)
     * @param nonce   nonce value (or null to omit)
     */
    fun toSignatureParameters(created: Long? = null, expires: Long? = null, nonce: String? = null): SignatureParameters {
        val b = SignatureParameters.builder()
            .components(components)
        if (keyId != null) b.keyId(keyId)
        if (algorithm != null) b.algorithm(algorithm)
        if (tag != null) b.tag(tag)
        if (created != null) b.createdEpoch(created)
        if (expires != null) b.expiresEpoch(expires)
        if (nonce != null) b.nonce(nonce)
        return b.build()
    }
}

/**
 * Accept-Signature header support per RFC 9421 Section 5.
 *
 * Provides building and parsing of Accept-Signature headers using the
 * [SignatureRequirements] type for both verification filtering and
 * signature negotiation.
 */
object AcceptSignature {

    /**
     * Build an Accept-Signature header value from a map of label to requirements.
     *
     * @param entries map of signature label to requirements
     * @return the serialized Accept-Signature header value
     */
    fun build(entries: Map<String, SignatureRequirements>): String {
        val members = entries.map { (label, req) -> toDictMember(label, req) }
        return SFV.serializeDictionary(members)
    }

    /**
     * Parse an Accept-Signature header value.
     *
     * @param headerValue the raw header value
     * @return map of signature label to requirements (preserving order)
     * @throws HttpSigException if the header is malformed
     */
    fun parse(headerValue: String): Map<String, SignatureRequirements> {
        val dictMembers = SFV.parseDictionary(headerValue)
        val result = linkedMapOf<String, SignatureRequirements>()
        for (member in dictMembers) {
            result[member.key] = fromDictMember(member)
        }
        return result
    }

    private fun toDictMember(label: String, req: SignatureRequirements): SFV.DictMember {
        // build inner list items from components
        val items = req.components.map { cid ->
            val itemParams = LinkedHashMap<String, Any?>(cid.params)
            SFV.Item(
                cid.name,
                if (itemParams.isEmpty()) SFV.Params.EMPTY else SFV.Params(itemParams),
            )
        }

        // build inner list params
        val listParams = linkedMapOf<String, Any?>()
        if (req.keyId != null) {
            listParams["keyid"] = req.keyId
        }
        if (req.algorithm != null) {
            listParams["alg"] = req.algorithm.value
        }
        if (req.requireCreated) {
            listParams["created"] = true
        }
        if (req.requireExpires) {
            listParams["expires"] = true
        }
        if (req.tag != null) {
            listParams["tag"] = req.tag
        }

        val innerList = SFV.InnerList(items, SFV.Params(listParams))
        return SFV.DictMember(label, innerList)
    }

    private fun fromDictMember(member: SFV.DictMember): SignatureRequirements {
        val innerList = member.value as? SFV.InnerList
            ?: throw HttpSigException("Accept-Signature entry '${member.key}' is not an inner list")

        // extract components
        val components = innerList.items.map { item ->
            val name = item.value as? String
                ?: throw HttpSigException("component identifier must be a string")
            val paramMap = LinkedHashMap<String, Any>(item.params.map.mapValues { it.value as Any })
            ComponentIdentifier.withParams(name, paramMap)
        }

        // extract params
        val params = innerList.params
        val keyId = params["keyid"] as? String
        val algStr = params["alg"] as? String
        val algorithm = algStr?.let { Algorithm.fromValue(it) }
        val tag = params["tag"] as? String
        val requireCreated = params["created"] == true
        val requireExpires = params["expires"] == true

        return SignatureRequirements(
            components = components,
            keyId = keyId,
            algorithm = algorithm,
            tag = tag,
            requireCreated = requireCreated,
            requireExpires = requireExpires,
        )
    }
}
