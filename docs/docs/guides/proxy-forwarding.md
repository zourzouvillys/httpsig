---
sidebar_position: 4
---

# Proxy Forwarding

How to forward a verified signed request through a reverse proxy (or API gateway) while adding headers and preserving the original client signature.

## The Problem

A reverse proxy sits between the client and the upstream service. When the client signs its request, the proxy needs to:

1. **Verify** the client's signature (reject bad requests early).
2. **Add headers** the upstream needs (e.g. `Forwarded`, `X-Tenant-Id`).
3. **Preserve** the original client signature so the upstream can independently verify the client's identity.
4. **Add its own signature** covering both the new headers and the original signature, so the upstream knows the proxy vouches for the additions.

```
Client                     Proxy                       Upstream
  |                          |                            |
  |  POST /api               |                            |
  |  Signature-Input: sig1   |                            |
  |  Signature: sig1=:...:   |                            |
  |  ----------------------> |                            |
  |                          |                            |
  |          1. Verify sig1 with client's public key      |
  |          2. Add Forwarded + X-Tenant-Id headers       |
  |          3. Sign as "proxy" covering new headers      |
  |             + original sig1 input                     |
  |                          |                            |
  |                          |  POST /api                 |
  |                          |  Forwarded: ...            |
  |                          |  X-Tenant-Id: acme         |
  |                          |  Signature-Input: sig1=...,|
  |                          |                  proxy=... |
  |                          |  Signature: sig1=:....:,   |
  |                          |             proxy=:....:   |
  |                          |  ----------------------->  |
  |                          |                            |
  |                          |     4. Verify "proxy" sig  |
  |                          |     5. Optionally verify   |
  |                          |        sig1 too            |
```

RFC 9421 supports this natively through **multiple signatures** on the same message. Each signature gets a distinct label, its own set of covered components, and its own key. They coexist in the `Signature-Input` and `Signature` dictionary headers.

## Strategy

The proxy's signature should cover:

| Component | Why |
|---|---|
| New headers (`forwarded`, `x-tenant-id`) | Proves the proxy set them and they haven't been tampered with in transit. |
| Original request identity (`@method`, `@path`, `@authority`) | Binds the proxy signature to the same request the client signed, preventing the proxy sig from being grafted onto a different request. |
| `"signature";key="sig1"` | **Binds** the proxy signature to the client's exact signature bytes. If anyone strips or modifies `sig1`, the proxy signature breaks. |
| `"signature-input";key="sig1"` | Binds to the client's signature parameters. Prevents an attacker from swapping the client's signature input while keeping the proxy sig intact. |

The `;key` parameter (RFC 9421 Section 2.1.3) extracts a single member from a Dictionary Structured Field header. Since `Signature` and `Signature-Input` are both SFV dictionaries keyed by label, `"signature";key="sig1"` resolves to the client's raw signature bytes and `"signature-input";key="sig1"` resolves to their serialized parameters.

This is the standards-compliant way to create a cryptographic binding between signatures.

## Proxy Implementation

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

The proxy verifies the incoming client signature, adds new headers, then creates its own signature bound to the original.

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
func proxyRoundTrip(
	req *http.Request,
	clientKeyProvider httpsig.KeyProvider,
	proxyKey httpsig.SigningKey,
	next http.RoundTripper,
) (*http.Response, error) {
	msg := &httpsig.RequestMessage{Req: req}

	// Step 1: Verify the client's signature.
	clientResult, err := httpsig.VerifyMessage(msg, clientKeyProvider, &httpsig.VerifyOptions{
		RequiredComponents: []httpsig.ComponentIdentifier{
			httpsig.Component("@method"),
			httpsig.Component("@authority"),
		},
		RequiredLabel: "sig1",
		MaxAge:        5 * time.Minute,
		MaxClockSkew:  30 * time.Second,
		RejectExpired: httpsig.BoolPtr(true),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("client signature verification failed: %w", err)
	}

	// Step 2: Add proxy headers.
	req.Header.Set("Forwarded", fmt.Sprintf(
		"for=%s;proto=%s;host=%s",
		req.RemoteAddr, req.URL.Scheme, req.Host,
	))
	req.Header.Set("X-Tenant-Id", resolveTenant(clientResult.KeyID))

	// Step 3: Sign as the proxy.
	// Cover new headers, request identity, and the client's signature.
	proxyParams := httpsig.SignatureParameters{
		Components: []httpsig.ComponentIdentifier{
			httpsig.Component("@method"),
			httpsig.Component("@path"),
			httpsig.Component("@authority"),
			httpsig.Component("forwarded"),
			httpsig.Component("x-tenant-id"),
			httpsig.ComponentWithKey("signature", "sig1"),
			httpsig.ComponentWithKey("signature-input", "sig1"),
		},
		KeyID:   "proxy-key-1",
		Created: httpsig.Int64Ptr(time.Now().Unix()),
		Tag:     httpsig.StringPtr("forwarded"),
	}

	msg = &httpsig.RequestMessage{Req: req}
	proxyResult, err := httpsig.SignMessage(msg, "proxy", proxyParams, proxyKey, nil)
	if err != nil {
		return nil, fmt.Errorf("proxy signing failed: %w", err)
	}

	// Step 4: Append the proxy signature (preserve the client's).
	existingSigInput := req.Header.Get("Signature-Input")
	existingSig := req.Header.Get("Signature")
	req.Header.Set("Signature-Input",
		existingSigInput+", "+httpsig.SignatureInputHeader(proxyResult))
	req.Header.Set("Signature",
		existingSig+", "+httpsig.SignatureHeader(proxyResult))

	return next.RoundTrip(req)
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
  component,
  componentWithKey,
} from '@zourzouvillys/httpsig';

async function proxyRequest(
  incomingHeaders: Headers,
  method: string,
  url: URL,
  clientKeyProvider: KeyProvider,
  proxyKey: SigningKey,
): Promise<Headers> {
  const msg = {
    isRequest: true,
    method,
    url,
    headerValues: (name: string) => {
      const v = incomingHeaders.get(name);
      return v ? [v] : [];
    },
  };

  // Step 1: Verify the client's signature.
  const clientResult = await verifyMessage(msg, clientKeyProvider, {
    requiredComponents: [component('@method'), component('@authority')],
    requiredLabel: 'sig1',
    maxAgeMs: 5 * 60 * 1000,
    maxClockSkewMs: 30_000,
    rejectExpired: true,
  });

  // Step 2: Add proxy headers.
  const outHeaders = new Headers(incomingHeaders);
  outHeaders.set('Forwarded', `for=client;proto=https;host=${url.host}`);
  outHeaders.set('X-Tenant-Id', resolveTenant(clientResult.keyId));

  // Step 3: Sign as the proxy.
  const outMsg = {
    isRequest: true,
    method,
    url,
    headerValues: (name: string) => {
      const v = outHeaders.get(name);
      return v ? [v] : [];
    },
  };

  const proxyResult = await signMessage(outMsg, 'proxy', {
    components: [
      component('@method'),
      component('@path'),
      component('@authority'),
      component('forwarded'),
      component('x-tenant-id'),
      componentWithKey('signature', 'sig1'),
      componentWithKey('signature-input', 'sig1'),
    ],
    keyId: 'proxy-key-1',
    created: Math.floor(Date.now() / 1000),
    tag: 'forwarded',
  }, proxyKey);

  // Step 4: Append the proxy signature (preserve the client's).
  const existingSigInput = outHeaders.get('Signature-Input') ?? '';
  const existingSig = outHeaders.get('Signature') ?? '';
  outHeaders.set('Signature-Input',
    existingSigInput + ', ' + signatureInputHeader(proxyResult));
  outHeaders.set('Signature',
    existingSig + ', ' + signatureHeader(proxyResult));

  return outHeaders;
}
```

</TabItem>
<TabItem value="java" label="Java">

```java
import io.zrz.httpsig.*;
import java.time.Instant;
import java.util.List;

public HttpMessage proxyRequest(
    HttpMessage incomingMsg,
    KeyProvider clientKeyProvider,
    SigningKey proxyKey
) throws HttpSigException {
    // Step 1: Verify the client's signature.
    var clientResult = Verifier.verify(incomingMsg, clientKeyProvider,
        new Verifier.VerifyOptions(
            List.of(
                ComponentIdentifier.of("@method"),
                ComponentIdentifier.of("@authority")
            ),
            Duration.ofMinutes(5),
            Duration.ofSeconds(30),
            true,
            "sig1",
            null
        ), null);

    // Step 2: Add proxy headers.
    var outMsg = RawMessage.from(incomingMsg);
    outMsg.setHeader("Forwarded", "for=client;proto=https;host=" + outMsg.authority());
    outMsg.setHeader("X-Tenant-Id", resolveTenant(clientResult.keyId()));

    // Step 3: Sign as the proxy.
    var proxyParams = SignatureParameters.builder()
        .component("@method")
        .component("@path")
        .component("@authority")
        .component("forwarded")
        .component("x-tenant-id")
        .component(ComponentIdentifier.withKey("signature", "sig1"))
        .component(ComponentIdentifier.withKey("signature-input", "sig1"))
        .keyId("proxy-key-1")
        .created(Instant.now())
        .tag("forwarded")
        .build();

    var proxyResult = Signer.sign(outMsg, "proxy", proxyParams, proxyKey, null);

    // Step 4: Append the proxy signature (preserve the client's).
    outMsg.appendHeader("Signature-Input", Signer.signatureInputHeader(proxyResult));
    outMsg.appendHeader("Signature", Signer.signatureHeader(proxyResult));

    return outMsg;
}
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
import HTTPSig
import Foundation

func proxyRequest(
    incoming: URLRequest,
    clientKeyProvider: some KeyProvider,
    proxyKey: some SigningKey
) throws -> URLRequest {
    let msg = URLRequestMessage(incoming)

    // Step 1: Verify the client's signature.
    let clientResult = try Verifier.verify(
        msg: msg,
        provider: clientKeyProvider,
        options: VerifyOptions(
            requiredComponents: [.init("@method"), .init("@authority")],
            maxAge: 300,
            maxClockSkew: 30,
            requiredLabel: "sig1"
        )
    )

    // Step 2: Add proxy headers.
    var outReq = incoming
    outReq.setValue(
        "for=client;proto=https;host=\(incoming.url!.host()!)",
        forHTTPHeaderField: "Forwarded"
    )
    outReq.setValue(
        resolveTenant(clientResult.keyId),
        forHTTPHeaderField: "X-Tenant-Id"
    )

    // Step 3: Sign as the proxy.
    let outMsg = URLRequestMessage(outReq)
    let proxyParams = SignatureParameters(
        components: [
            .init("@method"),
            .init("@path"),
            .init("@authority"),
            .init("forwarded"),
            .init("x-tenant-id"),
            .withKey("signature", key: "sig1"),
            .withKey("signature-input", key: "sig1"),
        ],
        keyId: "proxy-key-1",
        created: Int64(Date().timeIntervalSince1970),
        tag: "forwarded"
    )

    let proxyResult = try Signer.sign(
        msg: outMsg, label: "proxy", params: proxyParams, key: proxyKey
    )

    // Step 4: Append the proxy signature (preserve the client's).
    let existingSigInput = outReq.value(forHTTPHeaderField: "Signature-Input") ?? ""
    let existingSig = outReq.value(forHTTPHeaderField: "Signature") ?? ""
    outReq.setValue(
        existingSigInput + ", " + Signer.signatureInputHeader(proxyResult),
        forHTTPHeaderField: "Signature-Input"
    )
    outReq.setValue(
        existingSig + ", " + Signer.signatureHeader(proxyResult),
        forHTTPHeaderField: "Signature"
    )

    return outReq
}
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
import io.zrz.httpsig.*
import java.time.Duration
import java.time.Instant

fun proxyRequest(
    incomingMsg: HttpMessage,
    clientKeyProvider: KeyProvider,
    proxyKey: SigningKey,
): HttpMessage {
    // Step 1: Verify the client's signature.
    val clientResult = Verifier.verify(incomingMsg, clientKeyProvider,
        Verifier.VerifyOptions(
            requiredComponents = listOf(
                ComponentIdentifier.of("@method"),
                ComponentIdentifier.of("@authority"),
            ),
            maxAge = Duration.ofMinutes(5),
            maxClockSkew = Duration.ofSeconds(30),
            rejectExpired = true,
            requiredLabel = "sig1",
        )
    )

    // Step 2: Add proxy headers.
    val outMsg = RawMessage.from(incomingMsg)
    outMsg.setHeader("Forwarded", "for=client;proto=https;host=${outMsg.authority()}")
    outMsg.setHeader("X-Tenant-Id", resolveTenant(clientResult.keyId))

    // Step 3: Sign as the proxy.
    val proxyParams = SignatureParameters.builder()
        .component("@method")
        .component("@path")
        .component("@authority")
        .component("forwarded")
        .component("x-tenant-id")
        .component(ComponentIdentifier.withKey("signature", "sig1"))
        .component(ComponentIdentifier.withKey("signature-input", "sig1"))
        .keyId("proxy-key-1")
        .created(Instant.now())
        .tag("forwarded")
        .build()

    val proxyResult = Signer.sign(outMsg, "proxy", proxyParams, proxyKey)

    // Step 4: Append the proxy signature (preserve the client's).
    outMsg.appendHeader("Signature-Input", Signer.signatureInputHeader(proxyResult))
    outMsg.appendHeader("Signature", Signer.signatureHeader(proxyResult))

    return outMsg
}
```

</TabItem>
</Tabs>

### What the wire looks like

After the proxy forwards the request, the upstream sees:

```http
POST /api/resource HTTP/1.1
Host: upstream.internal
Forwarded: for=203.0.113.50:4321;proto=https;host=api.example.com
X-Tenant-Id: acme
Content-Type: application/json
Signature-Input: sig1=("@method" "@path" "@authority" "content-type");created=1730000000;keyid="client-a",
                 proxy=("@method" "@path" "@authority" "forwarded" "x-tenant-id"
                   "signature";key="sig1" "signature-input";key="sig1");created=1730000060;keyid="proxy-key-1";tag="forwarded"
Signature: sig1=:OGllY2VzLW9mLWVpZ2h0...:, proxy=:dGhpcyBpcyB0aGUgcH...:
```

Two signatures, one message. The upstream can verify either or both.

## Upstream Verification

The upstream verifies the proxy signature (and optionally the client signature) independently.

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
func upstreamHandler(w http.ResponseWriter, r *http.Request) {
	msg := &httpsig.RequestMessage{Req: r}

	// Verify the proxy's signature (covers forwarded + x-tenant-id + client sig binding).
	_, err := httpsig.VerifyMessage(msg, proxyKeyProvider, &httpsig.VerifyOptions{
		RequiredComponents: []httpsig.ComponentIdentifier{
			httpsig.Component("@method"),
			httpsig.Component("@authority"),
			httpsig.Component("forwarded"),
			httpsig.Component("x-tenant-id"),
			httpsig.ComponentWithKey("signature", "sig1"),
			httpsig.ComponentWithKey("signature-input", "sig1"),
		},
		RequiredLabel: "proxy",
		MaxAge:        5 * time.Minute,
	}, nil)
	if err != nil {
		http.Error(w, "proxy signature invalid", http.StatusBadGateway)
		return
	}

	// Proxy sig is valid: forwarded, x-tenant-id, and sig1 are all trustworthy.
	// Optionally verify the client's original signature too:
	clientResult, err := httpsig.VerifyMessage(msg, clientKeyProvider, &httpsig.VerifyOptions{
		RequiredLabel: "sig1",
		MaxAge:        10 * time.Minute,
	}, nil)
	if err != nil {
		http.Error(w, "client signature invalid", http.StatusUnauthorized)
		return
	}

	tenantID := r.Header.Get("X-Tenant-Id")
	fmt.Fprintf(w, "ok: tenant=%s, client=%s", tenantID, clientResult.KeyID)
}
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
const proxyResult = await verifyMessage(msg, proxyKeyProvider, {
  requiredComponents: [
    component('@method'),
    component('@authority'),
    component('forwarded'),
    component('x-tenant-id'),
    componentWithKey('signature', 'sig1'),
    componentWithKey('signature-input', 'sig1'),
  ],
  requiredLabel: 'proxy',
  maxAgeMs: 5 * 60 * 1000,
});

// Proxy sig valid. Optionally verify the client too:
const clientResult = await verifyMessage(msg, clientKeyProvider, {
  requiredLabel: 'sig1',
  maxAgeMs: 10 * 60 * 1000,
});
```

</TabItem>
<TabItem value="java" label="Java">

```java
var proxyResult = Verifier.verify(msg, proxyKeyProvider,
    new Verifier.VerifyOptions(
        List.of(
            ComponentIdentifier.of("@method"),
            ComponentIdentifier.of("@authority"),
            ComponentIdentifier.of("forwarded"),
            ComponentIdentifier.of("x-tenant-id"),
            ComponentIdentifier.withKey("signature", "sig1"),
            ComponentIdentifier.withKey("signature-input", "sig1")
        ),
        Duration.ofMinutes(5),
        null,
        true,
        "proxy",
        null
    ), null);

// Proxy sig valid. Optionally verify the client too:
var clientResult = Verifier.verify(msg, clientKeyProvider,
    new Verifier.VerifyOptions(
        List.of(), Duration.ofMinutes(10), null, true, "sig1", null
    ), null);
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
let _ = try Verifier.verify(
    msg: msg,
    provider: proxyKeyProvider,
    options: VerifyOptions(
        requiredComponents: [
            .init("@method"),
            .init("@authority"),
            .init("forwarded"),
            .init("x-tenant-id"),
            .withKey("signature", key: "sig1"),
            .withKey("signature-input", key: "sig1"),
        ],
        maxAge: 300,
        requiredLabel: "proxy"
    )
)

// Proxy sig valid. Optionally verify the client too:
let clientResult = try Verifier.verify(
    msg: msg,
    provider: clientKeyProvider,
    options: VerifyOptions(requiredLabel: "sig1", maxAge: 600)
)
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
Verifier.verify(msg, proxyKeyProvider,
    Verifier.VerifyOptions(
        requiredComponents = listOf(
            ComponentIdentifier.of("@method"),
            ComponentIdentifier.of("@authority"),
            ComponentIdentifier.of("forwarded"),
            ComponentIdentifier.of("x-tenant-id"),
            ComponentIdentifier.withKey("signature", "sig1"),
            ComponentIdentifier.withKey("signature-input", "sig1"),
        ),
        maxAge = Duration.ofMinutes(5),
        requiredLabel = "proxy",
    )
)

// Proxy sig valid. Optionally verify the client too:
val clientResult = Verifier.verify(msg, clientKeyProvider,
    Verifier.VerifyOptions(
        requiredLabel = "sig1",
        maxAge = Duration.ofMinutes(10),
    )
)
```

</TabItem>
</Tabs>

## Security Considerations

### Always bind to the original signature

The proxy's covered components **must** include `"signature";key="sig1"` and `"signature-input";key="sig1"`. Without this binding, an attacker could:

- Strip the client's `sig1` and replace it with a signature from a different client.
- Modify the client's `Signature-Input` to claim different covered components.
- Replay the proxy's signature with a completely different client signature attached.

The `;key` binding makes the proxy's signature invalid if any byte of the client's signature or its parameters changes.

### Do not re-sign the entire message from scratch

A common mistake is to strip the client's signature and create a single new proxy signature. This destroys the chain of trust: the upstream can no longer independently verify who the original client was. It also means the proxy has to be fully trusted for client identity, which defeats the purpose of end-to-end signatures.

### Preserve the original Signature-Input and Signature

The proxy must not overwrite the existing `Signature-Input` or `Signature` headers. These are SFV dictionaries, so new entries are appended with a comma. If you `Set` instead of appending, you destroy the client's signature.

### Use the `tag` parameter

Setting `tag="forwarded"` on the proxy signature lets the upstream distinguish it from other signatures by purpose, not just by label name. This is useful when multiple intermediaries each add their own signatures.

### Validate before forwarding

Always verify the client's signature **before** forwarding. A proxy that blindly adds its own signature to an unverified request is vouching for something it hasn't checked. The upstream trusts the proxy sig as an assertion that the proxy did its due diligence.

### Content-Digest for body integrity

If the request has a body, the client should include `content-digest` in their signed components. The proxy should verify it (RFC 9530), and include `content-digest` in the proxy signature's covered components too, to guarantee the body wasn't modified in transit.
