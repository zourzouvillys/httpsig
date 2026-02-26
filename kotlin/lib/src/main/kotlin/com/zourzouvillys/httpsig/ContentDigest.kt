package com.zourzouvillys.httpsig

import java.security.MessageDigest
import java.util.Base64

/**
 * Content-Digest header support per RFC 9530.
 *
 * Computes and verifies digest values for HTTP message bodies,
 * typically used alongside HTTP signatures to bind the body.
 */
object ContentDigest {

    /**
     * Digest algorithm identifiers.
     */
    enum class DigestAlgorithm(val sfvName: String, private val javaName: String) {
        SHA_256("sha-256", "SHA-256"),
        SHA_512("sha-512", "SHA-512");

        internal fun digest(body: ByteArray): ByteArray =
            MessageDigest.getInstance(javaName).digest(body)
    }

    /**
     * Compute a Content-Digest header value for the given body.
     *
     * @return a complete header value, e.g. "sha-256=:base64digest:"
     */
    fun compute(body: ByteArray, alg: DigestAlgorithm): String {
        val digest = alg.digest(body)
        val b64 = Base64.getEncoder().encodeToString(digest)
        return "${alg.sfvName}=:$b64:"
    }

    /**
     * Verify a Content-Digest header value against a body.
     *
     * The header value may contain multiple digest entries (SFV Dictionary).
     * Returns true if at least one recognized algorithm matches.
     */
    fun verify(body: ByteArray, headerValue: String): Boolean {
        val entries = SFV.parseDictionary(headerValue)
        var anyChecked = false

        for (entry in entries) {
            val alg = findAlgorithm(entry.key) ?: continue
            anyChecked = true

            val expectedDigest = when (val v = entry.value) {
                is SFV.Item -> v.value as? ByteArray
                    ?: throw HttpSigException("invalid digest value for ${entry.key}")
                else -> throw HttpSigException("invalid digest value for ${entry.key}")
            }

            val actual = alg.digest(body)
            if (!MessageDigest.isEqual(actual, expectedDigest)) {
                return false
            }
        }

        if (!anyChecked) {
            throw HttpSigException("no recognized digest algorithm in Content-Digest header")
        }
        return true
    }

    private fun findAlgorithm(name: String): DigestAlgorithm? =
        DigestAlgorithm.entries.firstOrNull { it.sfvName == name }
}
