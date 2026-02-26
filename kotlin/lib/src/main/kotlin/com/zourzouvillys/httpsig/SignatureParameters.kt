package com.zourzouvillys.httpsig

import java.time.Instant

/**
 * Parameters that control signature creation: which components to sign,
 * which algorithm/key to advertise, and optional metadata like created/expires.
 */
data class SignatureParameters(
    val components: List<ComponentIdentifier>,
    val algorithm: Algorithm? = null,
    val keyId: String? = null,
    val created: Long? = null,
    val expires: Long? = null,
    val nonce: String? = null,
    val tag: String? = null,
) {
    class Builder {
        private val components = mutableListOf<ComponentIdentifier>()
        private var algorithm: Algorithm? = null
        private var keyId: String? = null
        private var created: Long? = null
        private var expires: Long? = null
        private var nonce: String? = null
        private var tag: String? = null

        fun component(c: ComponentIdentifier) = apply { components.add(c) }
        fun component(name: String) = apply { components.add(ComponentIdentifier.of(name)) }
        fun components(cs: List<ComponentIdentifier>) = apply { components.addAll(cs) }
        fun algorithm(algorithm: Algorithm) = apply { this.algorithm = algorithm }
        fun keyId(keyId: String) = apply { this.keyId = keyId }
        fun created(created: Instant) = apply { this.created = created.epochSecond }
        fun createdEpoch(created: Long) = apply { this.created = created }
        fun expires(expires: Instant) = apply { this.expires = expires.epochSecond }
        fun expiresEpoch(expires: Long) = apply { this.expires = expires }
        fun nonce(nonce: String) = apply { this.nonce = nonce }
        fun tag(tag: String) = apply { this.tag = tag }

        fun build(): SignatureParameters = SignatureParameters(
            components = components.toList(),
            algorithm = algorithm,
            keyId = keyId,
            created = created,
            expires = expires,
            nonce = nonce,
            tag = tag,
        )
    }

    companion object {
        fun builder(): Builder = Builder()
    }
}
