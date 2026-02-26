package io.zrz.httpsig.okhttp

import io.zrz.httpsig.Keys
import io.zrz.httpsig.SignatureParameters
import io.zrz.httpsig.Verifier
import io.zrz.httpsig.RawMessage
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.URI

class SigningInterceptorTest {

    private lateinit var server: MockWebServer
    private val secret = "super-secret-key-that-is-at-least-256-bits-long!!".toByteArray()
    private val key = Keys.hmacSHA256Key("test-key", secret)

    @BeforeEach
    fun setUp() {
        server = MockWebServer()
        server.start()
    }

    @AfterEach
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `interceptor adds signature headers to request`() {
        server.enqueue(MockResponse().setResponseCode(200))

        val client = OkHttpClient.Builder()
            .addInterceptor(
                SigningInterceptor(key) { _ ->
                    SignatureParameters.builder()
                        .component("@method")
                        .component("@authority")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            )
            .build()

        val request = Request.Builder()
            .url(server.url("/test"))
            .get()
            .build()

        client.newCall(request).execute().use { response ->
            assertEquals(200, response.code)
        }

        val recorded = server.takeRequest()
        assertNotNull(recorded.getHeader("Signature-Input"))
        assertNotNull(recorded.getHeader("Signature"))
        assertTrue(recorded.getHeader("Signature-Input")!!.startsWith("sig1="))
        assertTrue(recorded.getHeader("Signature")!!.startsWith("sig1="))
    }

    @Test
    fun `signed request can be verified`() {
        server.enqueue(MockResponse().setResponseCode(200))

        val client = OkHttpClient.Builder()
            .addInterceptor(
                SigningInterceptor(key, "hmac-sig") { _ ->
                    SignatureParameters.builder()
                        .component("@method")
                        .component("@authority")
                        .component("@path")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            )
            .build()

        val request = Request.Builder()
            .url(server.url("/verify-me"))
            .get()
            .build()

        client.newCall(request).execute().close()

        val recorded = server.takeRequest()
        val sigInput = recorded.getHeader("Signature-Input")!!
        val sig = recorded.getHeader("Signature")!!

        // reconstruct the message on the "server side" and verify the signature
        val serverMsg = RawMessage.request(
            recorded.method!!,
            URI.create(recorded.requestUrl.toString()),
            mapOf(
                "signature-input" to listOf(sigInput),
                "signature" to listOf(sig),
            ),
        )

        val result = Verifier.verify(serverMsg, { _, _ -> key })
        assertEquals("hmac-sig", result.label)
        assertEquals("test-key", result.keyId)
    }

    @Test
    fun `custom label is used in headers`() {
        server.enqueue(MockResponse().setResponseCode(200))

        val client = OkHttpClient.Builder()
            .addInterceptor(
                SigningInterceptor(key, "my-label") { _ ->
                    SignatureParameters.builder()
                        .component("@method")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            )
            .build()

        val request = Request.Builder()
            .url(server.url("/label-test"))
            .get()
            .build()

        client.newCall(request).execute().close()

        val recorded = server.takeRequest()
        assertTrue(recorded.getHeader("Signature-Input")!!.startsWith("my-label="))
        assertTrue(recorded.getHeader("Signature")!!.startsWith("my-label="))
    }

    @Test
    fun `paramsFactory receives the original request`() {
        server.enqueue(MockResponse().setResponseCode(200))

        var capturedMethod: String? = null
        var capturedPath: String? = null

        val client = OkHttpClient.Builder()
            .addInterceptor(
                SigningInterceptor(key) { req ->
                    capturedMethod = req.method
                    capturedPath = req.url.encodedPath
                    SignatureParameters.builder()
                        .component("@method")
                        .keyId("test-key")
                        .createdEpoch(1618884473)
                        .build()
                }
            )
            .build()

        val request = Request.Builder()
            .url(server.url("/factory-test"))
            .get()
            .build()

        client.newCall(request).execute().close()

        assertEquals("GET", capturedMethod)
        assertEquals("/factory-test", capturedPath)
    }
}
