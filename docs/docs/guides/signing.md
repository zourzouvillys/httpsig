---
sidebar_position: 1
---

# Signing Requests

This guide walks through signing HTTP requests in all five languages.

## Step 1: Create a Signing Key

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
import (
    "crypto/ed25519"
    "github.com/zourzouvillys/httpsig/golang"
)

_, privateKey, _ := ed25519.GenerateKey(nil)
key := httpsig.NewEd25519SigningKey("my-key-id", privateKey)
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import * as crypto from 'node:crypto';
import { newEd25519SigningKey } from '@zourzouvillys/httpsig';

const { privateKey } = crypto.generateKeyPairSync('ed25519');
const key = newEd25519SigningKey('my-key-id', privateKey);
```

</TabItem>
<TabItem value="java" label="Java">

```java
import com.zourzouvillys.httpsig.Keys;
import java.security.KeyPairGenerator;

var keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
var key = Keys.ed25519SigningKey("my-key-id", keyPair.getPrivate());
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
import HTTPSig
import CryptoKit

let privateKey = Curve25519.Signing.PrivateKey()
let key = Ed25519SigningKey(keyId: "my-key-id", privateKey: privateKey)
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
import com.zourzouvillys.httpsig.Keys
import java.security.KeyPairGenerator

val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
val key = Keys.ed25519SigningKey("my-key-id", keyPair.private)
```

</TabItem>
</Tabs>

## Step 2: Define Signature Parameters

Signature parameters control which parts of the message are signed and what metadata is attached.

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
params := httpsig.SignatureParameters{
    Components: []httpsig.ComponentIdentifier{
        httpsig.Component("@method"),
        httpsig.Component("@path"),
        httpsig.Component("@authority"),
        httpsig.Component("content-type"),
    },
    KeyID:   "my-key-id",
    Created: httpsig.Int64Ptr(time.Now().Unix()),
}
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import { component } from '@zourzouvillys/httpsig';

const params = {
  components: [
    component('@method'),
    component('@path'),
    component('@authority'),
    component('content-type'),
  ],
  keyId: 'my-key-id',
  created: Math.floor(Date.now() / 1000),
};
```

</TabItem>
<TabItem value="java" label="Java">

```java
import com.zourzouvillys.httpsig.SignatureParameters;
import java.time.Instant;

var params = SignatureParameters.builder()
    .component("@method")
    .component("@path")
    .component("@authority")
    .component("content-type")
    .keyId("my-key-id")
    .created(Instant.now())
    .build();
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
let params = SignatureParameters(
    components: [
        .init("@method"),
        .init("@path"),
        .init("@authority"),
        .init("content-type"),
    ],
    keyId: "my-key-id",
    created: Int64(Date().timeIntervalSince1970)
)
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
import com.zourzouvillys.httpsig.SignatureParameters
import java.time.Instant

val params = SignatureParameters.builder()
    .component("@method")
    .component("@path")
    .component("@authority")
    .component("content-type")
    .keyId("my-key-id")
    .created(Instant.now())
    .build()
```

</TabItem>
</Tabs>

## Step 3: Sign the Message

<Tabs groupId="language">
<TabItem value="go" label="Go">

```go
msg := &httpsig.RequestMessage{Req: req}
result, err := httpsig.SignMessage(msg, "sig1", params, key, nil)
if err != nil {
    return err
}

req.Header.Set("Signature-Input", httpsig.SignatureInputHeader(result))
req.Header.Set("Signature", httpsig.SignatureHeader(result))
```

</TabItem>
<TabItem value="typescript" label="TypeScript">

```typescript
import { signMessage, signatureInputHeader, signatureHeader } from '@zourzouvillys/httpsig';

const msg = {
  isRequest: true,
  method: 'POST',
  url: new URL('https://example.com/api'),
  headerValues: (name: string) => {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    const v = headers[name.toLowerCase()];
    return v ? [v] : [];
  },
};

const result = await signMessage(msg, 'sig1', params, key);

// Add to your fetch/axios/undici request headers:
headers['Signature-Input'] = signatureInputHeader(result);
headers['Signature'] = signatureHeader(result);
```

</TabItem>
<TabItem value="java" label="Java">

```java
import com.zourzouvillys.httpsig.Signer;

Signer.SignResult result = Signer.sign(httpMessage, "sig1", params, key, null);

request.addHeader("Signature-Input", Signer.signatureInputHeader(result));
request.addHeader("Signature", Signer.signatureHeader(result));
```

</TabItem>
<TabItem value="swift" label="Swift">

```swift
let result = try Signer.sign(msg: httpMessage, label: "sig1", params: params, key: key)

request.addValue(Signer.signatureInputHeader(result), forHTTPHeaderField: "Signature-Input")
request.addValue(Signer.signatureHeader(result), forHTTPHeaderField: "Signature")
```

</TabItem>
<TabItem value="kotlin" label="Kotlin">

```kotlin
import com.zourzouvillys.httpsig.Signer

val result = Signer.sign(httpMessage, "sig1", params, key)

request.addHeader("Signature-Input", Signer.signatureInputHeader(result))
request.addHeader("Signature", Signer.signatureHeader(result))
```

</TabItem>
</Tabs>

## Multiple Signatures

A message can carry multiple signatures. Sign with different labels:

```go
result1, _ := httpsig.SignMessage(msg, "sig1", authParams, authKey, nil)
result2, _ := httpsig.SignMessage(msg, "audit", auditParams, auditKey, nil)

req.Header.Set("Signature-Input", httpsig.SignatureInputHeader(result1, result2))
req.Header.Set("Signature", httpsig.SignatureHeader(result1, result2))
```

## Including Body Integrity

To protect the message body, compute a `Content-Digest` first, set the header, then include `content-digest` in your signed components:

```go
body := []byte(`{"data": "value"}`)
digest, _ := httpsig.ContentDigest(body, httpsig.DigestSHA256)
req.Header.Set("Content-Digest", digest)

// Now include "content-digest" in params.Components and sign
```

See [Content-Digest](/docs/concepts/content-digest) for the full details.
