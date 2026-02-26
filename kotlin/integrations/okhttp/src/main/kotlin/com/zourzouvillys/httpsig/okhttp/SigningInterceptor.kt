package com.zourzouvillys.httpsig.okhttp

import com.zourzouvillys.httpsig.SignatureParameters
import com.zourzouvillys.httpsig.Signer
import com.zourzouvillys.httpsig.SigningKey
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response

/**
 * OkHttp [Interceptor] that signs outgoing requests per RFC 9421.
 *
 * Adds `Signature-Input` and `Signature` headers to every request that passes through.
 *
 * @param key the signing key to use
 * @param label the signature label (defaults to "sig1")
 * @param paramsFactory builds [SignatureParameters] for each request, so callers can
 *   vary components or metadata per-request if needed
 */
class SigningInterceptor(
    private val key: SigningKey,
    private val label: String = "sig1",
    private val paramsFactory: (Request) -> SignatureParameters,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val msg = OkHttpMessage(original)
        val params = paramsFactory(original)
        val result = Signer.sign(msg, label, params, key)

        val signed = original.newBuilder()
            .header("Signature-Input", Signer.signatureInputHeader(result))
            .header("Signature", Signer.signatureHeader(result))
            .build()

        return chain.proceed(signed)
    }
}
