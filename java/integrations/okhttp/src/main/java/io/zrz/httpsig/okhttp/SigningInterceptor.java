package io.zrz.httpsig.okhttp;

import java.io.IOException;
import java.util.function.Function;

import io.zrz.httpsig.HttpSigException;
import io.zrz.httpsig.SignatureParameters;
import io.zrz.httpsig.Signer;
import io.zrz.httpsig.SigningKey;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

/**
 * OkHttp {@link Interceptor} that signs outgoing requests with HTTP Message Signatures (RFC 9421).
 *
 * <pre>
 *   var interceptor = new SigningInterceptor(
 *       signingKey,
 *       req -> SignatureParameters.builder()
 *           .component("@method")
 *           .component("@authority")
 *           .keyId("my-key")
 *           .created(Instant.now())
 *           .build()
 *   );
 *
 *   var client = new OkHttpClient.Builder()
 *       .addInterceptor(interceptor)
 *       .build();
 * </pre>
 */
public final class SigningInterceptor implements Interceptor {

    private final SigningKey key;
    private final String label;
    private final Function<Request, SignatureParameters> paramsFactory;

    /**
     * @param key           the signing key
     * @param paramsFactory produces {@link SignatureParameters} for each request
     */
    public SigningInterceptor(SigningKey key, Function<Request, SignatureParameters> paramsFactory) {
        this(key, "sig1", paramsFactory);
    }

    /**
     * @param key           the signing key
     * @param label         the signature label (e.g. "sig1")
     * @param paramsFactory produces {@link SignatureParameters} for each request
     */
    public SigningInterceptor(SigningKey key, String label, Function<Request, SignatureParameters> paramsFactory) {
        this.key = key;
        this.label = label;
        this.paramsFactory = paramsFactory;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request original = chain.request();

        SignatureParameters params = paramsFactory.apply(original);
        var msg = new OkHttpMessage(original);

        Signer.SignResult result;
        try {
            result = Signer.sign(msg, label, params, key, null);
        } catch (HttpSigException e) {
            throw new IOException("failed to sign request", e);
        }

        Request signed = original.newBuilder()
            .addHeader("Signature-Input", Signer.signatureInputHeader(result))
            .addHeader("Signature", Signer.signatureHeader(result))
            .build();

        return chain.proceed(signed);
    }
}
