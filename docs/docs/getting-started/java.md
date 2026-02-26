---
sidebar_position: 3
---

# Java

## Installation

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("com.zourzouvillys:httpsig")

    // Optional integrations (pick what you need):
    implementation("com.zourzouvillys:httpsig-okhttp")
    implementation("com.zourzouvillys:httpsig-jdk-http")
    implementation("com.zourzouvillys:httpsig-spring-webclient")
}
```

### Gradle (Groovy)

```groovy
dependencies {
    implementation 'com.zourzouvillys:httpsig'
}
```

Requires Java 17 or later.

## Quick Example: Sign a Request

```java
import com.zourzouvillys.httpsig.*;
import java.time.Instant;

// Create a signing key (Ed25519)
SigningKey key = Keys.ed25519SigningKey("my-key-id", privateKey);

// Build signature parameters
var params = SignatureParameters.builder()
    .component("@method")
    .component("@path")
    .component("@authority")
    .component("content-type")
    .keyId("my-key-id")
    .created(Instant.now())
    .build();

// Sign the message
Signer.SignResult result = Signer.sign(httpMessage, "sig1", params, key, null);

// Apply headers to your HTTP request
request.addHeader("Signature-Input", Signer.signatureInputHeader(result));
request.addHeader("Signature", Signer.signatureHeader(result));
```

## Quick Example: Verify a Signature

```java
import com.zourzouvillys.httpsig.*;

// Set up a KeyProvider
KeyProvider provider = (keyId, algorithm) -> {
    if ("my-key-id".equals(keyId)) {
        return Keys.ed25519VerifyingKey(keyId, publicKey);
    }
    return null;
};

// Verify
var options = new Verifier.VerifyOptions(
    List.of(ComponentIdentifier.of("@method"), ComponentIdentifier.of("@authority")),
    Duration.ofMinutes(5),  // maxAge
    true,                   // rejectExpired
    null,                   // requiredLabel
    null                    // clock (defaults to Instant::now)
);

Verifier.VerifyResult result = Verifier.verify(httpMessage, provider, options, null);
System.out.println("Verified: label=" + result.label() + ", keyId=" + result.keyId());
```

## HTTP Client Integrations

Java has three integration modules:

### OkHttp

```java
import com.zourzouvillys.httpsig.okhttp.SigningInterceptor;

var interceptor = new SigningInterceptor(
    signingKey,
    req -> SignatureParameters.builder()
        .component("@method")
        .component("@authority")
        .keyId("my-key")
        .created(Instant.now())
        .build()
);

var client = new OkHttpClient.Builder()
    .addInterceptor(interceptor)
    .build();
```

### JDK HttpClient

```java
import com.zourzouvillys.httpsig.jdkhttp.HttpSigning;

var builder = HttpRequest.newBuilder()
    .uri(URI.create("https://example.com/api"))
    .header("Content-Type", "application/json")
    .GET();

HttpSigning.sign(builder, "sig1", params, signingKey);

var request = builder.build();
```

### Spring WebClient

```java
import com.zourzouvillys.httpsig.spring.SigningFilterFunction;

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
    .build();
```

See the [Integrations Guide](/docs/guides/integrations) for more details.
