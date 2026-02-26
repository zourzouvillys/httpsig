package io.zrz.httpsig.ktor

import io.zrz.httpsig.Keys
import io.zrz.httpsig.RawMessage
import io.zrz.httpsig.SignatureParameters
import io.zrz.httpsig.Verifier
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.URI

class HttpSigPluginTest {

    private val secret = "super-secret-key-that-is-at-least-256-bits-long!!".toByteArray()
    private val key = Keys.hmacSHA256Key("test-key", secret)

    @Test
    fun `plugin adds signature headers to request`() = runTest {
        var capturedSigInput: String? = null
        var capturedSig: String? = null

        val engine = MockEngine { request ->
            capturedSigInput = request.headers["Signature-Input"]
            capturedSig = request.headers["Signature"]
            respond("OK", HttpStatusCode.OK)
        }

        val client = HttpClient(engine) {
            install(HttpSig) {
                key = this@HttpSigPluginTest.key
                paramsFactory = { _ ->
                    SignatureParameters.builder()
                        .component("@method")
                        .component("@authority")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            }
        }

        client.get("https://example.com/test")

        assertNotNull(capturedSigInput)
        assertNotNull(capturedSig)
        assertTrue(capturedSigInput!!.startsWith("sig1="))
        assertTrue(capturedSig!!.startsWith("sig1="))
    }

    @Test
    fun `signed request can be verified`() = runTest {
        var capturedSigInput: String? = null
        var capturedSig: String? = null
        var capturedMethod: String? = null
        var capturedUrl: String? = null

        val engine = MockEngine { request ->
            capturedSigInput = request.headers["Signature-Input"]
            capturedSig = request.headers["Signature"]
            capturedMethod = request.method.value
            capturedUrl = request.url.toString()
            respond("OK", HttpStatusCode.OK)
        }

        val client = HttpClient(engine) {
            install(HttpSig) {
                key = this@HttpSigPluginTest.key
                label = "hmac-sig"
                paramsFactory = { _ ->
                    SignatureParameters.builder()
                        .component("@method")
                        .component("@authority")
                        .component("@path")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            }
        }

        client.get("https://example.com/verify-me")

        // reconstruct the message and verify the signature
        val serverMsg = RawMessage.request(
            capturedMethod!!,
            URI.create(capturedUrl!!),
            mapOf(
                "signature-input" to listOf(capturedSigInput!!),
                "signature" to listOf(capturedSig!!),
            ),
        )

        val result = Verifier.verify(serverMsg, { _, _ -> this@HttpSigPluginTest.key })
        assertEquals("hmac-sig", result.label)
        assertEquals("test-key", result.keyId)
    }

    @Test
    fun `custom label is used in headers`() = runTest {
        var capturedSigInput: String? = null
        var capturedSig: String? = null

        val engine = MockEngine { request ->
            capturedSigInput = request.headers["Signature-Input"]
            capturedSig = request.headers["Signature"]
            respond("OK", HttpStatusCode.OK)
        }

        val client = HttpClient(engine) {
            install(HttpSig) {
                key = this@HttpSigPluginTest.key
                label = "my-label"
                paramsFactory = { _ ->
                    SignatureParameters.builder()
                        .component("@method")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            }
        }

        client.get("https://example.com/label-test")

        assertTrue(capturedSigInput!!.startsWith("my-label="))
        assertTrue(capturedSig!!.startsWith("my-label="))
    }

    @Test
    fun `paramsFactory receives the request builder`() = runTest {
        var capturedMethod: String? = null
        var capturedUrl: String? = null

        val engine = MockEngine { respond("OK", HttpStatusCode.OK) }

        val client = HttpClient(engine) {
            install(HttpSig) {
                key = this@HttpSigPluginTest.key
                paramsFactory = { request ->
                    capturedMethod = request.method.value
                    capturedUrl = request.url.buildString()
                    SignatureParameters.builder()
                        .component("@method")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            }
        }

        client.get("https://example.com/factory-test")

        assertEquals("GET", capturedMethod)
        assertTrue(capturedUrl!!.contains("/factory-test"))
    }

    @Test
    fun `plugin signs POST requests with content-type`() = runTest {
        var capturedSigInput: String? = null
        var capturedSig: String? = null

        val engine = MockEngine { request ->
            capturedSigInput = request.headers["Signature-Input"]
            capturedSig = request.headers["Signature"]
            respond("OK", HttpStatusCode.OK)
        }

        val client = HttpClient(engine) {
            install(HttpSig) {
                key = this@HttpSigPluginTest.key
                paramsFactory = { _ ->
                    SignatureParameters.builder()
                        .component("@method")
                        .component("@authority")
                        .component("content-type")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            }
        }

        client.post("https://example.com/data") {
            header(HttpHeaders.ContentType, "application/json")
            setBody("{\"hello\": \"world\"}")
        }

        assertNotNull(capturedSigInput)
        assertNotNull(capturedSig)
        assertTrue(capturedSigInput!!.startsWith("sig1="))
    }
}
