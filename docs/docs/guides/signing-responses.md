---
sidebar_position: 5
---

# Signing Responses

How to sign HTTP responses so the client can verify that the response came from the expected server and is bound to the exact request it sent.

## Why Sign Responses?

Request signing proves the client's identity to the server. Response signing does the opposite: it proves the server's identity to the client and guarantees the response hasn't been tampered with. Combined with request binding, it also guarantees this response was produced for *this specific request*, preventing replay.

```
Client                                 Server
  |                                      |
  |  POST /transfer                      |
  |  Signature-Input: sig1=...           |
  |  Signature: sig1=:...:              |
  |  -------------------------------->   |
  |                                      |
  |      1. Verify sig1                  |
  |      2. Process request              |
  |      3. Sign response, binding to    |
  |         the request's sig1           |
  |                                      |
  |  200 OK                              |
  |  Signature-Input: resp=...           |
  |  Signature: resp=:...:              |
  |  <--------------------------------   |
  |                                      |
  |  4. Verify resp signature            |
  |  5. Confirm it's bound to sig1       |
  |     (our original request)           |
```

## Binding to the Request

Response signatures use the `;req` parameter to include components from the original request in the signature base. This prevents an attacker from replaying a valid signed response against a different request.

At minimum, a response signature should cover:

| Component | Why |
|---|---|
| `@status` | Proves the status code hasn't been changed. |
| Response headers (e.g. `content-type`, `content-digest`) | Proves the response body and type are authentic. |
| `"@method";req`, `"@authority";req` | Binds the response to the specific request method and target. |
| `"signature";req;key="sig1"` | Binds to the client's *exact* signature bytes. Without this, an attacker could replay the response against a different request from the same client. |
| `"signature-input";req;key="sig1"` | Binds to the client's signature parameters (covered components, created timestamp, etc.). Prevents swapping the client's signature-input while keeping the response signature intact. |

The `;req;key` combination is what makes response signatures truly secure. The `;req` flag tells the signer/verifier to look at the request message instead of the response, and `;key` extracts a specific entry from the `Signature` or `Signature-Input` dictionary header by label.

## Server Implementation

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

The server verifies the incoming request signature, processes the request, then signs the response binding it to the original request signature.

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
func handler(w http.ResponseWriter, r *http.Request) {
	reqMsg := &httpsig.RequestMessage{Req: r}

	// Step 1: Verify the client's request signature.
	_, err := httpsig.VerifyMessage(reqMsg, clientKeyProvider, &httpsig.VerifyOptions{
		RequiredComponents: []httpsig.ComponentIdentifier{
			httpsig.Component("@method"),
			httpsig.Component("@authority"),
		},
		RequiredLabel: "sig1",
		MaxAge:        5 * time.Minute,
	}, nil)
	if err != nil {
		http.Error(w, "request signature invalid", http.StatusUnauthorized)
		return
	}

	// Step 2: Process the request, produce the response body.
	body := []byte(`{"status": "ok"}`)
	digest, _ := httpsig.ContentDigest(body, httpsig.DigestSHA256)

	// Step 3: Build and sign the response.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Digest", digest)

	respMsg := &httpsig.RawMessage{
		IsReq:  false,
		Status: 200,
		Headers: http.Header{
			"Content-Type":   {w.Header().Get("Content-Type")},
			"Content-Digest": {w.Header().Get("Content-Digest")},
			// The response message also needs the request's Signature
			// and Signature-Input headers for ;req;key extraction.
			"Signature":       r.Header.Values("Signature"),
			"Signature-Input": r.Header.Values("Signature-Input"),
		},
	}

	params := httpsig.SignatureParameters{
		Components: []httpsig.ComponentIdentifier{
			httpsig.Component("@status"),
			httpsig.Component("content-type"),
			httpsig.Component("content-digest"),
			// Bind to request identity.
			httpsig.ComponentReq("@method"),
			httpsig.ComponentReq("@authority"),
			// Bind to the client's exact signature.
			httpsig.ComponentReqWithKey("signature", "sig1"),
			httpsig.ComponentReqWithKey("signature-input", "sig1"),
		},
		KeyID:   "server-key-1",
		Created: httpsig.Int64Ptr(time.Now().Unix()),
	}

	result, err := httpsig.SignMessage(respMsg, "resp", params, serverKey, reqMsg)
	if err != nil {
		http.Error(w, "response signing failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Signature-Input", httpsig.SignatureInputHeader(result))
	w.Header().Set("Signature", httpsig.SignatureHeader(result))
	w.WriteHeader(200)
	w.Write(body)
}
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import {
  verifyMessage,
  signMessage,
  signatureInputHeader,
  signatureHeader,
  contentDigest,
  component,
  componentReq,
  componentReqWithKey,
  buildResponseMessage,
} from '@zourzouvillys/httpsig';

async function handleRequest(
  reqMsg: HttpMessage,
  serverKey: SigningKey,
  clientKeyProvider: KeyProvider,
): Promise<{ status: number; headers: Record<string, string>; body: string }> {
  // Step 1: Verify the client's request signature.
  await verifyMessage(reqMsg, clientKeyProvider, {
    requiredComponents: [component('@method'), component('@authority')],
    requiredLabel: 'sig1',
    maxAgeMs: 5 * 60 * 1000,
  });

  // Step 2: Process the request, produce the response body.
  const body = JSON.stringify({ status: 'ok' });
  const digest = contentDigest(new TextEncoder().encode(body), 'sha-256');

  // Step 3: Build and sign the response.
  const respMsg = buildResponseMessage(200, [
    ['content-type', 'application/json'],
    ['content-digest', digest],
  ]);

  const result = await signMessage(respMsg, 'resp', {
    components: [
      component('@status'),
      component('content-type'),
      component('content-digest'),
      componentReq('@method'),
      componentReq('@authority'),
      componentReqWithKey('signature', 'sig1'),
      componentReqWithKey('signature-input', 'sig1'),
    ],
    keyId: 'server-key-1',
    created: Math.floor(Date.now() / 1000),
  }, serverKey, reqMsg);

  return {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Content-Digest': digest,
      'Signature-Input': signatureInputHeader(result),
      'Signature': signatureHeader(result),
    },
    body,
  };
}
```

</TabItem>
<TabItem value="java" label="Java">

```java
import io.zrz.httpsig.*;
import java.time.Instant;

Signer.SignResult signResponse(
    HttpMessage reqMsg,
    HttpMessage respMsg,
    SigningKey serverKey
) {
    var params = SignatureParameters.builder()
        .component("@status")
        .component("content-type")
        .component("content-digest")
        .component(ComponentIdentifier.req("@method"))
        .component(ComponentIdentifier.req("@authority"))
        .component(ComponentIdentifier.reqWithKey("signature", "sig1"))
        .component(ComponentIdentifier.reqWithKey("signature-input", "sig1"))
        .keyId("server-key-1")
        .created(Instant.now())
        .build();

    return Signer.sign(respMsg, "resp", params, serverKey, reqMsg);
}
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
import HTTPSig
import Foundation

func signResponse(
    reqMsg: some HttpMessage,
    respMsg: some HttpMessage,
    serverKey: some SigningKey
) throws -> Signer.SignResult {
    let params = SignatureParameters(
        components: [
            .init("@status"),
            .init("content-type"),
            .init("content-digest"),
            .req("@method"),
            .req("@authority"),
            .reqWithKey("signature", key: "sig1"),
            .reqWithKey("signature-input", key: "sig1"),
        ],
        keyId: "server-key-1",
        created: Int64(Date().timeIntervalSince1970)
    )

    return try Signer.sign(
        msg: respMsg, label: "resp", params: params,
        key: serverKey, reqMsg: reqMsg
    )
}
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
import io.zrz.httpsig.*
import java.time.Instant

fun signResponse(
    reqMsg: HttpMessage,
    respMsg: HttpMessage,
    serverKey: SigningKey,
): Signer.SignResult {
    val params = SignatureParameters.builder()
        .component("@status")
        .component("content-type")
        .component("content-digest")
        .component(ComponentIdentifier.req("@method"))
        .component(ComponentIdentifier.req("@authority"))
        .component(ComponentIdentifier.reqWithKey("signature", "sig1"))
        .component(ComponentIdentifier.reqWithKey("signature-input", "sig1"))
        .keyId("server-key-1")
        .created(Instant.now())
        .build()

    return Signer.sign(respMsg, "resp", params, serverKey, reqMsg)
}
```

</TabItem>
</Tabs>

### What the wire looks like

The signed response on the wire:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Digest: sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:
Signature-Input: resp=("@status" "content-type" "content-digest"
                   "@method";req "@authority";req
                   "signature";req;key="sig1" "signature-input";req;key="sig1");created=1730000060;keyid="server-key-1"
Signature: resp=:dGhpcyBpcyB0aGUgcmVzcG9uc2Ugc2ln...:
```

The signature base the server computed includes values from both the response and the original request:

```
"@status": 200
"content-type": application/json
"content-digest": sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:
"@method";req: POST
"@authority";req: api.example.com
"signature";req;key="sig1": :Y2xpZW50IHNpZyBieXRlcw==:
"signature-input";req;key="sig1": ("@method" "@authority" "content-type");created=1730000000;keyid="client-a"
"@signature-params": ("@status" "content-type" "content-digest" "@method";req "@authority";req "signature";req;key="sig1" "signature-input";req;key="sig1");created=1730000060;keyid="server-key-1"
```

## Client Verification

The client verifies the response signature by passing the original request as the `reqMsg` parameter, allowing the verifier to reconstruct the `;req` components.

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
// resp is *http.Response, req is the original *http.Request.
respMsg := &httpsig.ResponseMessage{Resp: resp, Req: req}
reqMsg := &httpsig.RequestMessage{Req: req}

result, err := httpsig.VerifyMessage(respMsg, serverKeyProvider, &httpsig.VerifyOptions{
	RequiredComponents: []httpsig.ComponentIdentifier{
		httpsig.Component("@status"),
		httpsig.Component("content-type"),
		httpsig.ComponentReq("@method"),
		httpsig.ComponentReq("@authority"),
		httpsig.ComponentReqWithKey("signature", "sig1"),
		httpsig.ComponentReqWithKey("signature-input", "sig1"),
	},
	RequiredLabel: "resp",
	MaxAge:        5 * time.Minute,
}, reqMsg)
if err != nil {
	// response signature invalid or not bound to our request
}
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
const result = await verifyMessage(respMsg, serverKeyProvider, {
  requiredComponents: [
    component('@status'),
    component('content-type'),
    componentReq('@method'),
    componentReq('@authority'),
    componentReqWithKey('signature', 'sig1'),
    componentReqWithKey('signature-input', 'sig1'),
  ],
  requiredLabel: 'resp',
  maxAgeMs: 5 * 60 * 1000,
}, reqMsg);
```

</TabItem>
<TabItem value="java" label="Java">

```java
var result = Verifier.verify(respMsg, serverKeyProvider,
    new Verifier.VerifyOptions(
        List.of(
            ComponentIdentifier.of("@status"),
            ComponentIdentifier.of("content-type"),
            ComponentIdentifier.req("@method"),
            ComponentIdentifier.req("@authority"),
            ComponentIdentifier.reqWithKey("signature", "sig1"),
            ComponentIdentifier.reqWithKey("signature-input", "sig1")
        ),
        Duration.ofMinutes(5),
        null,
        true,
        "resp",
        null
    ), reqMsg);
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
let result = try Verifier.verify(
    msg: respMsg,
    provider: serverKeyProvider,
    options: VerifyOptions(
        requiredComponents: [
            .init("@status"),
            .init("content-type"),
            .req("@method"),
            .req("@authority"),
            .reqWithKey("signature", key: "sig1"),
            .reqWithKey("signature-input", key: "sig1"),
        ],
        maxAge: 300,
        requiredLabel: "resp"
    ),
    reqMsg: reqMsg
)
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
val result = Verifier.verify(respMsg, serverKeyProvider,
    Verifier.VerifyOptions(
        requiredComponents = listOf(
            ComponentIdentifier.of("@status"),
            ComponentIdentifier.of("content-type"),
            ComponentIdentifier.req("@method"),
            ComponentIdentifier.req("@authority"),
            ComponentIdentifier.reqWithKey("signature", "sig1"),
            ComponentIdentifier.reqWithKey("signature-input", "sig1"),
        ),
        maxAge = Duration.ofMinutes(5),
        requiredLabel = "resp",
    ),
    reqMsg
)
```

</TabItem>
</Tabs>

## Security Considerations

### Always bind to the request signature, not just request components

Using `"@method";req` and `"@authority";req` alone only proves the response was for *some* POST to api.example.com. An attacker who intercepts multiple request/response pairs could swap responses between different requests to the same endpoint.

Adding `"signature";req;key="sig1"` and `"signature-input";req;key="sig1"` binds to the client's *exact* signature bytes and parameters, which include the `created` timestamp and nonce. This makes each request/response pair cryptographically unique.

### Include Content-Digest for body integrity

The response signature covers headers, not the body directly. To protect the response body, compute a `Content-Digest` (RFC 9530), set the header, and include `content-digest` in the signed components. The client should verify the digest matches the body after verifying the signature.

### The reqMsg parameter is required

When verifying a response signature that includes `;req` components, you must pass the original request as the `reqMsg` parameter to `VerifyMessage`. Without it, the verifier can't reconstruct the signature base and verification will fail.

This means the client must hold onto its original request (including the `Signature` and `Signature-Input` headers it sent) until the response is verified.

### Response-only signatures (without request binding)

If the response doesn't need to be bound to a specific request (e.g. a static resource), you can omit the `;req` components entirely:

```go
params := httpsig.SignatureParameters{
	Components: []httpsig.ComponentIdentifier{
		httpsig.Component("@status"),
		httpsig.Component("content-type"),
		httpsig.Component("content-digest"),
	},
	KeyID:   "server-key-1",
	Created: httpsig.Int64Ptr(time.Now().Unix()),
}

result, err := httpsig.SignMessage(respMsg, "resp", params, serverKey, nil)
```

This still proves the response came from the server and hasn't been tampered with, but it doesn't tie the response to any particular request.
