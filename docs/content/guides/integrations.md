---
sidebar_position: 3
---

# HTTP Client Integrations

Each language provides drop-in integrations with popular HTTP clients. These handle the signing plumbing so you do not need to manually construct messages and apply headers.

## Go: net/http

### Signing Client (Transport)

`Transport` wraps any `http.RoundTripper` to sign outgoing requests:

```go
import "github.com/zourzouvillys/httpsig/golang"

client := &http.Client{
    Transport: &httpsig.Transport{
        Key: signingKey,
        // Optional: customize label (default "sig1")
        Label: "sig1",
        // Optional: customize parameters per request
        Params: func(req *http.Request) httpsig.SignatureParameters {
            return httpsig.SignatureParameters{
                Components: []httpsig.ComponentIdentifier{
                    httpsig.Component("@method"),
                    httpsig.Component("@path"),
                    httpsig.Component("@authority"),
                    httpsig.Component("content-type"),
                },
                KeyID:   signingKey.KeyID(),
                Created: httpsig.Int64Ptr(time.Now().Unix()),
            }
        },
    },
}

resp, err := client.Post("https://example.com/api", "application/json", body)
```

If `Params` is nil, the default signs `@method`, `@path`, and `@authority` with the current timestamp.

### Verifying Server (Middleware)

`RequireSignature` returns standard `http.Handler` middleware:

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/resource", handleResource)

protected := httpsig.RequireSignature(keyProvider, &httpsig.VerifyOptions{
    RequiredComponents: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@authority"),
    },
    MaxAge: 5 * time.Minute,
})(mux)

http.ListenAndServe(":8080", protected)
```

For custom error handling, use `VerifyMiddleware` directly:

```go
middleware := &httpsig.VerifyMiddleware{
    Provider: keyProvider,
    Options:  verifyOpts,
    OnError: func(w http.ResponseWriter, r *http.Request, err error) {
        http.Error(w, "invalid signature: "+err.Error(), http.StatusForbidden)
    },
}
http.ListenAndServe(":8080", middleware.Wrap(mux))
```

## TypeScript: fetch

`createSigningFetch` returns a `fetch`-compatible function:

```typescript
import { createSigningFetch } from '@zourzouvillys/httpsig/fetch';

const signedFetch = createSigningFetch({
  key: signingKey,
  label: 'sig1',
  // Optional: customize parameters per request
  params: (request) => ({
    components: [
      component('@method'),
      component('@path'),
      component('@authority'),
      component('content-type'),
    ],
    keyId: 'my-key-id',
    created: Math.floor(Date.now() / 1000),
  }),
});

const response = await signedFetch('https://example.com/api', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ data: 'value' }),
});
```

## TypeScript: axios

`addSigningInterceptor` registers a request interceptor on an axios instance:

```typescript
import axios from 'axios';
import { addSigningInterceptor } from '@zourzouvillys/httpsig/axios';

const client = axios.create({ baseURL: 'https://api.example.com' });

const interceptorId = addSigningInterceptor(client, {
  key: signingKey,
  label: 'sig1',
});

// All requests through this instance are now signed
const response = await client.post('/resource', { data: 'value' });

// To remove later:
// client.interceptors.request.eject(interceptorId);
```

## TypeScript: undici

`createSigningRequest` wraps undici's `request` function:

```typescript
import { request } from 'undici';
import { createSigningRequest } from '@zourzouvillys/httpsig/undici';

const signedRequest = createSigningRequest(request, {
  key: signingKey,
});

const { statusCode, body } = await signedRequest('https://example.com/api', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ data: 'value' }),
});
```

## Java: OkHttp

`SigningInterceptor` implements OkHttp's `Interceptor` interface:

```java
import io.zrz.httpsig.okhttp.SigningInterceptor;

var interceptor = new SigningInterceptor(
    signingKey,
    req -> SignatureParameters.builder()
        .component("@method")
        .component("@authority")
        .component("content-type")
        .keyId("my-key")
        .created(Instant.now())
        .build()
);

var client = new OkHttpClient.Builder()
    .addInterceptor(interceptor)
    .build();

var request = new Request.Builder()
    .url("https://example.com/api")
    .post(RequestBody.create(json, MediaType.parse("application/json")))
    .build();

var response = client.newCall(request).execute();
```

## Java: JDK HttpClient

`HttpSigning` signs a `HttpRequest.Builder` in place:

```java
import io.zrz.httpsig.jdkhttp.HttpSigning;

var builder = HttpRequest.newBuilder()
    .uri(URI.create("https://example.com/api"))
    .header("Content-Type", "application/json")
    .POST(HttpRequest.BodyPublishers.ofString(json));

HttpSigning.sign(builder, params, signingKey);

var request = builder.build();
var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
```

## Java: Spring WebClient

`SigningFilterFunction` implements `ExchangeFilterFunction`:

```java
import io.zrz.httpsig.spring.SigningFilterFunction;

var filter = new SigningFilterFunction(
    signingKey,
    req -> SignatureParameters.builder()
        .component("@method")
        .component("@authority")
        .keyId("my-key")
        .created(Instant.now())
        .build()
);

var client = WebClient.builder()
    .filter(filter)
    .baseUrl("https://example.com")
    .build();

var result = client.post()
    .uri("/api/resource")
    .contentType(MediaType.APPLICATION_JSON)
    .bodyValue(requestBody)
    .retrieve()
    .bodyToMono(String.class)
    .block();
```

## Swift: URLSession

The `HTTPSigURLSession` module extends `URLRequest` with a `signed()` method:

```swift
import HTTPSigURLSession

var request = URLRequest(url: URL(string: "https://example.com/api")!)
request.httpMethod = "POST"
request.setValue("application/json", forHTTPHeaderField: "Content-Type")
request.httpBody = jsonData

let signed = try request.signed(label: "sig1", params: params, key: signingKey)

let (data, response) = try await URLSession.shared.data(for: signed)
```

## Swift: Alamofire

The `HTTPSigAlamofire` module provides a `SigningInterceptor` that conforms to `RequestInterceptor`:

```swift
import Alamofire
import HTTPSigAlamofire

let interceptor = SigningInterceptor(
    key: signingKey,
    label: "sig1",
    params: params
)

// Use as a session-level interceptor
let session = Session(interceptor: interceptor)

let response = await session.request(
    "https://example.com/api",
    method: .post,
    parameters: ["data": "value"],
    encoding: JSONEncoding.default
).serializingData().response
```

## Kotlin: OkHttp

The Kotlin OkHttp integration mirrors the Java one with Kotlin-idiomatic syntax:

```kotlin
import io.zrz.httpsig.okhttp.SigningInterceptor

val interceptor = SigningInterceptor(
    key = signingKey,
    paramsFactory = { request ->
        SignatureParameters.builder()
            .component("@method")
            .component("@authority")
            .component("content-type")
            .keyId("my-key")
            .created(Instant.now())
            .build()
    }
)

val client = OkHttpClient.Builder()
    .addInterceptor(interceptor)
    .build()

val request = Request.Builder()
    .url("https://example.com/api")
    .post(json.toRequestBody("application/json".toMediaType()))
    .build()

val response = client.newCall(request).execute()
```

## Integration Summary

| Language   | HTTP Client         | Integration Type           | Module/Import                           |
|------------|---------------------|----------------------------|-----------------------------------------|
| Go         | net/http (client)   | `Transport` (RoundTripper) | `httpsig`                               |
| Go         | net/http (server)   | `RequireSignature` middleware | `httpsig`                            |
| TypeScript | fetch               | Wrapper function           | `@zourzouvillys/httpsig/fetch`          |
| TypeScript | axios               | Request interceptor        | `@zourzouvillys/httpsig/axios`          |
| TypeScript | undici              | Wrapper function           | `@zourzouvillys/httpsig/undici`         |
| Java       | OkHttp              | `Interceptor`              | `httpsig-okhttp`                        |
| Java       | JDK HttpClient      | Builder helper             | `httpsig-jdk-http`                      |
| Java       | Spring WebClient    | `ExchangeFilterFunction`   | `httpsig-spring-webclient`              |
| Swift      | URLSession          | `URLRequest.signed()`      | `HTTPSigURLSession`                     |
| Swift      | Alamofire           | `RequestInterceptor`       | `HTTPSigAlamofire`                      |
| Kotlin     | OkHttp              | `Interceptor`              | `httpsig-kotlin-okhttp`                 |
