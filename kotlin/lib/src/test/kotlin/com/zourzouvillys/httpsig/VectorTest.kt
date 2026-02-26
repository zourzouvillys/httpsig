package com.zourzouvillys.httpsig

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import java.io.ByteArrayOutputStream
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.stream.Stream

/**
 * Loads the shared RFC 9421 test vectors from testdata/vectors/ and validates:
 * - Signature base construction matches expected bytes
 * - Deterministic algorithms produce the exact expected signature
 * - All signatures round-trip through sign/verify
 * - Pre-computed verify-only signatures verify correctly
 */
class VectorTest {

    companion object {
        private val TESTDATA: Path = Path.of("../../testdata")
        private val MAPPER = ObjectMapper()
    }

    @TestFactory
    fun signatureBaseTests(): Stream<DynamicTest> =
        loadVectors().map { v ->
            DynamicTest.dynamicTest("${v.id} - signature base") {
                val msg = buildMessage(v.message)
                val reqMsg = v.requestMessage?.let { buildMessage(it) }
                val params = buildParams(v)
                val base = SignatureBase.build(msg, params, reqMsg)
                assertEquals(v.expectedBase, String(base.base, StandardCharsets.UTF_8))
            }
        }

    @TestFactory
    fun signatureInputTests(): Stream<DynamicTest> =
        loadVectors().map { v ->
            DynamicTest.dynamicTest("${v.id} - signature input") {
                val params = buildParams(v)
                val sigInput = SignatureBase.buildSignatureInput(params)
                // expectedSignatureInput is "label=input", strip the label
                val expected = v.expectedSignatureInput.substring(
                    v.expectedSignatureInput.indexOf('=') + 1
                )
                assertEquals(expected, sigInput)
            }
        }

    @TestFactory
    fun deterministicSignatureTests(): Stream<DynamicTest> =
        loadVectors()
            .filter { it.deterministic }
            .map { v ->
                DynamicTest.dynamicTest("${v.id} - deterministic signature") {
                    val msg = buildMessage(v.message)
                    val reqMsg = v.requestMessage?.let { buildMessage(it) }
                    val params = buildParams(v)
                    val signingKey = loadSigningKey(v)

                    val result = Signer.sign(msg, v.label, params, signingKey, reqMsg)
                    val actual = Base64.getEncoder().encodeToString(result.signature)
                    assertEquals(v.expectedSignature, actual)
                }
            }

    @TestFactory
    fun verifyPrecomputedTests(): Stream<DynamicTest> =
        loadVectors()
            .filter { it.verifyOnlySignature != null }
            .map { v ->
                DynamicTest.dynamicTest("${v.id} - verify precomputed") {
                    val reqMsg = v.requestMessage?.let { buildMessage(it) }
                    val verifyingKey = loadVerifyingKey(v)

                    val sigInputVal = v.expectedSignatureInput.substring(
                        v.expectedSignatureInput.indexOf('=') + 1
                    )
                    val sigInputHeader = "${v.label}=$sigInputVal"
                    val sigHeader = "${v.label}=:${v.verifyOnlySignature}:"

                    val signedMsg = addSignatureHeaders(v.message, sigInputHeader, sigHeader)
                    val result = Verifier.verify(
                        signedMsg,
                        { _, _ -> verifyingKey },
                        Verifier.VerifyOptions.defaults(),
                        reqMsg,
                    )

                    assertEquals(v.label, result.label)
                }
            }

    @TestFactory
    fun roundTripTests(): Stream<DynamicTest> =
        loadVectors().map { v ->
            DynamicTest.dynamicTest("${v.id} - round trip") {
                val msg = buildMessage(v.message)
                val reqMsg = v.requestMessage?.let { buildMessage(it) }
                val params = buildParams(v)
                val signingKey = loadSigningKey(v)
                val verifyingKey = loadVerifyingKey(v)

                val result = Signer.sign(msg, v.label, params, signingKey, reqMsg)
                val sigInputHeader = Signer.signatureInputHeader(result)
                val sigHeader = Signer.signatureHeader(result)

                val signedMsg = addSignatureHeaders(v.message, sigInputHeader, sigHeader)
                val verifyResult = Verifier.verify(
                    signedMsg,
                    { _, _ -> verifyingKey },
                    Verifier.VerifyOptions.defaults(),
                    reqMsg,
                )

                assertEquals(v.label, verifyResult.label)
                assertEquals(v.keyId, verifyResult.keyId)
            }
        }

    // ---- Vector loading ----

    private fun loadVectors(): Stream<Vector> {
        val vectorDir = TESTDATA.resolve("vectors")
        return Files.list(vectorDir)
            .filter { it.toString().endsWith(".json") }
            .sorted()
            .map { path ->
                try {
                    parseVector(MAPPER.readTree(path.toFile()))
                } catch (e: Exception) {
                    throw RuntimeException("failed to parse $path", e)
                }
            }
    }

    private fun parseVector(root: JsonNode): Vector {
        val sp = root["signingParams"]

        val components = mutableListOf<ComponentIdentifier>()
        for (comp in sp["components"]) {
            if (comp.isTextual) {
                components.add(ComponentIdentifier.of(comp.asText()))
            } else {
                val name = comp["name"].asText()
                val params = linkedMapOf<String, Any>()
                val paramsNode = comp["params"]
                paramsNode.fieldNames().forEach { k ->
                    params[k] = paramsNode[k].asText()
                }
                components.add(ComponentIdentifier.withParams(name, params))
            }
        }

        return Vector(
            id = root["id"].asText(),
            description = root["description"].asText(),
            message = root["message"],
            requestMessage = root["requestMessage"],
            expectedBase = root["expectedBase"].asText(),
            expectedSignatureInput = root["expectedSignatureInput"].asText(),
            deterministic = root["deterministic"].asBoolean(),
            expectedSignature = root["expectedSignature"]?.asText(),
            verifyOnlySignature = root["verifyOnlySignature"]?.asText(),
            label = sp["label"].asText(),
            keyId = sp["keyId"].asText(),
            algorithm = sp["algorithm"].asText(),
            created = if (sp.has("created")) sp["created"].asLong() else null,
            nonce = sp["nonce"]?.asText(),
            tag = sp["tag"]?.asText(),
            components = components,
            keyFile = root["keyFile"]?.asText(),
            pubKeyFile = root["pubKeyFile"]?.asText(),
        )
    }

    // ---- Message building ----

    private fun buildMessage(msg: JsonNode): HttpMessage {
        val type = msg["type"].asText()
        val headersNode = msg["headers"]

        val headers = linkedMapOf<String, MutableList<String>>()
        headersNode?.forEach { entry ->
            val name = entry[0].asText()
            val value = entry[1].asText()
            headers.getOrPut(name) { mutableListOf() }.add(value)
        }

        return if (type == "request") {
            val method = msg["method"].asText()
            val url = URI.create(msg["url"].asText())
            RawMessage.request(method, url, headers)
        } else {
            val statusCode = msg["statusCode"].asInt()
            RawMessage.response(statusCode, headers)
        }
    }

    private fun addSignatureHeaders(
        origMsg: JsonNode,
        sigInputHeader: String,
        sigHeader: String,
    ): HttpMessage {
        val type = origMsg["type"].asText()
        val headersNode = origMsg["headers"]

        val headers = linkedMapOf<String, MutableList<String>>()
        headersNode?.forEach { entry ->
            val name = entry[0].asText()
            val value = entry[1].asText()
            headers.getOrPut(name) { mutableListOf() }.add(value)
        }
        headers["signature-input"] = mutableListOf(sigInputHeader)
        headers["signature"] = mutableListOf(sigHeader)

        return if (type == "request") {
            val method = origMsg["method"].asText()
            val url = URI.create(origMsg["url"].asText())
            RawMessage.request(method, url, headers)
        } else {
            val statusCode = origMsg["statusCode"].asInt()
            RawMessage.response(statusCode, headers)
        }
    }

    // ---- Params building ----

    private fun buildParams(v: Vector): SignatureParameters {
        val builder = SignatureParameters.builder()
        for (comp in v.components) {
            builder.component(comp)
        }
        builder.keyId(v.keyId)
        // the "algorithm" field in the vector JSON is for key selection,
        // NOT for the `alg` signature parameter.
        v.created?.let { builder.createdEpoch(it) }
        v.nonce?.let { builder.nonce(it) }
        v.tag?.let { builder.tag(it) }
        return builder.build()
    }

    // ---- Key loading ----

    private fun loadSigningKey(v: Vector): SigningKey {
        val alg = Algorithm.fromValue(v.algorithm)
        return when (alg) {
            Algorithm.HmacSha256 -> {
                val secret = loadHmacSecret()
                Keys.hmacSHA256Key(v.keyId, secret)
            }
            Algorithm.Ed25519 -> {
                val pk = loadPkcs8PrivateKey(TESTDATA.resolve(v.keyFile!!), "Ed25519")
                Keys.ed25519SigningKey(v.keyId, pk)
            }
            Algorithm.RsaPssSha512 -> {
                val pk = loadPkcs8PrivateKey(TESTDATA.resolve(v.keyFile!!), "RSA")
                Keys.rsaPSSSigningKey(v.keyId, pk)
            }
            Algorithm.EcdsaP256Sha256 -> {
                val pk = loadEcPrivateKey(TESTDATA.resolve(v.keyFile!!))
                Keys.ecdsaP256SigningKey(v.keyId, pk)
            }
        }
    }

    private fun loadVerifyingKey(v: Vector): VerifyingKey {
        val alg = Algorithm.fromValue(v.algorithm)
        return when (alg) {
            Algorithm.HmacSha256 -> {
                val secret = loadHmacSecret()
                Keys.hmacSHA256Key(v.keyId, secret)
            }
            Algorithm.Ed25519 -> {
                val pk = loadSpkiPublicKey(TESTDATA.resolve(v.pubKeyFile!!), "Ed25519")
                Keys.ed25519VerifyingKey(v.keyId, pk)
            }
            Algorithm.RsaPssSha512 -> {
                val pk = loadSpkiPublicKey(TESTDATA.resolve(v.pubKeyFile!!), "RSA")
                Keys.rsaPSSVerifyingKey(v.keyId, pk)
            }
            Algorithm.EcdsaP256Sha256 -> {
                val pk = loadSpkiPublicKey(TESTDATA.resolve(v.pubKeyFile!!), "EC")
                Keys.ecdsaP256VerifyingKey(v.keyId, pk)
            }
        }
    }

    private fun loadHmacSecret(): ByteArray {
        val b64 = Files.readString(TESTDATA.resolve("keys/hmac-secret.b64")).trim()
        return Base64.getDecoder().decode(b64)
    }

    private fun loadPkcs8PrivateKey(path: Path, algorithm: String): PrivateKey {
        val der = decodePem(Files.readString(path))
        val spec = PKCS8EncodedKeySpec(der)
        return try {
            KeyFactory.getInstance(algorithm).generatePrivate(spec)
        } catch (e: java.security.spec.InvalidKeySpecException) {
            // the key OID might be RSASSA-PSS while we tried RSA, or vice versa
            if (algorithm == "RSA") {
                KeyFactory.getInstance("RSASSA-PSS").generatePrivate(spec)
            } else {
                throw e
            }
        }
    }

    private fun loadEcPrivateKey(path: Path): PrivateKey {
        val pem = Files.readString(path)
        if (pem.contains("BEGIN EC PRIVATE KEY")) {
            // SEC1 format: wrap in PKCS#8 ASN.1 envelope
            val sec1Der = decodePem(pem)
            val pkcs8Der = wrapEc256Sec1ToPkcs8(sec1Der)
            val spec = PKCS8EncodedKeySpec(pkcs8Der)
            return KeyFactory.getInstance("EC").generatePrivate(spec)
        }
        // already PKCS#8
        return loadPkcs8PrivateKey(path, "EC")
    }

    private fun loadSpkiPublicKey(path: Path, algorithm: String): PublicKey {
        val der = decodePem(Files.readString(path))
        val spec = X509EncodedKeySpec(der)
        return KeyFactory.getInstance(algorithm).generatePublic(spec)
    }

    private fun decodePem(pem: String): ByteArray {
        val b64 = pem.replace(Regex("-----[A-Z ]+-----"), "")
            .replace(Regex("\\s+"), "")
        return Base64.getDecoder().decode(b64)
    }

    /**
     * Wraps a SEC1 EC private key in a PKCS#8 envelope for P-256.
     *
     *   SEQUENCE {
     *     INTEGER 0
     *     SEQUENCE { OID ecPublicKey, OID prime256v1 }
     *     OCTET STRING { <sec1-key-bytes> }
     *   }
     */
    private fun wrapEc256Sec1ToPkcs8(sec1Der: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()

        // version INTEGER 0
        val version = byteArrayOf(0x02, 0x01, 0x00)

        // AlgorithmIdentifier SEQUENCE
        val algId = byteArrayOf(
            0x30, 0x13,
            // OID 1.2.840.10045.2.1 (ecPublicKey)
            0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
            // OID 1.2.840.10045.3.1.7 (prime256v1)
            0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07,
        )

        // OCTET STRING wrapping the SEC1 key
        val octetStringHeader = if (sec1Der.size < 128) {
            byteArrayOf(0x04, sec1Der.size.toByte())
        } else {
            byteArrayOf(0x04, 0x81.toByte(), sec1Der.size.toByte())
        }

        val totalSeqContent = version.size + algId.size + octetStringHeader.size + sec1Der.size

        // outer SEQUENCE header
        if (totalSeqContent < 128) {
            out.write(byteArrayOf(0x30, totalSeqContent.toByte()))
        } else {
            out.write(byteArrayOf(0x30, 0x81.toByte(), totalSeqContent.toByte()))
        }

        out.write(version)
        out.write(algId)
        out.write(octetStringHeader)
        out.write(sec1Der)

        return out.toByteArray()
    }

    // ---- Test vector data holder ----

    private data class Vector(
        val id: String,
        val description: String,
        val message: JsonNode,
        val requestMessage: JsonNode?,
        val expectedBase: String,
        val expectedSignatureInput: String,
        val deterministic: Boolean,
        val expectedSignature: String?,
        val verifyOnlySignature: String?,
        val label: String,
        val keyId: String,
        val algorithm: String,
        val created: Long?,
        val nonce: String?,
        val tag: String?,
        val components: List<ComponentIdentifier>,
        val keyFile: String?,
        val pubKeyFile: String?,
    )
}
