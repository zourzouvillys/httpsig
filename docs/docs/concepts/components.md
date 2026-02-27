---
sidebar_position: 2
---

# Components

Components are the parts of an HTTP message that get included in a signature. RFC 9421 defines two categories: derived components (prefixed with `@`) and header fields.

## Derived Components

Derived components are computed from the HTTP message structure rather than from a specific header.

| Component         | Description                            | Request | Response |
|-------------------|----------------------------------------|---------|----------|
| `@method`         | HTTP method (GET, POST, etc.)          | Yes     | No       |
| `@target-uri`     | Full target URI                        | Yes     | No       |
| `@authority`      | Host (and port if non-default)         | Yes     | No       |
| `@scheme`         | URI scheme (http or https)             | Yes     | No       |
| `@request-target` | Request target (path + query)          | Yes     | No       |
| `@path`           | URI path component                     | Yes     | No       |
| `@query`          | Query string (including leading `?`)   | Yes     | No       |
| `@query-param`    | Individual query parameter (with `;name`) | Yes  | No       |
| `@status`         | Response status code                   | No      | Yes      |

### Usage in Code

All languages provide helpers to create component identifiers:

```go
// Go
httpsig.Component("@method")
httpsig.Component("@authority")
httpsig.QueryParam("search")                     // @query-param;name="search"
httpsig.ComponentReq("@method")                  // @method;req (for response signatures)
httpsig.ComponentWithKey("signature", "sig1")     // "signature";key="sig1" (dictionary member)
```

```typescript
// TypeScript
import { component, queryParam, componentReq, componentWithKey } from '@zourzouvillys/httpsig';

component('@method');
component('@authority');
queryParam('search');                              // @query-param;name="search"
componentReq('@method');                          // @method;req
componentWithKey('signature', 'sig1');             // "signature";key="sig1"
```

```java
// Java
ComponentIdentifier.of("@method");
ComponentIdentifier.of("@authority");
ComponentIdentifier.queryParam("search");
ComponentIdentifier.req("@method");
ComponentIdentifier.withKey("signature", "sig1");  // "signature";key="sig1"
```

## Header Fields

Any HTTP header can be included as a component. Header names are lowercased:

```
"content-type": application/json
"content-length": 42
```

When a message has multiple values for the same header, they are combined with `, ` per RFC 9421 Section 2.1.

## Header Field Parameters

Header components support optional parameters that modify how the value is extracted:

### `;sf` (Structured Fields)

Parse the header as a Structured Field Value and re-serialize it. This normalizes whitespace and formatting:

```
"cache-control";sf: max-age=60, must-revalidate
```

### `;bs` (Byte Sequence)

Wrap each header value in SFV byte sequence encoding (base64 between colons):

```
"example-header";bs: :dGhlIHZhbHVl:
```

### `;key` (Dictionary Key)

Extract a single member from a Dictionary structured field:

```
"example-dict";key="member-name": the-value
```

### `;req` (Request Binding)

In a response signature, include a component from the associated request message rather than the response:

```
"@method";req: POST
```

This binds the response signature to the specific request that triggered it.

## Choosing Components

At minimum, request signatures should cover `@method` and `@authority` to prevent the signature from being replayed against a different endpoint. Common choices:

**Minimal:**
```
("@method" "@authority")
```

**Standard (recommended):**
```
("@method" "@path" "@authority")
```

**With body integrity:**
```
("@method" "@path" "@authority" "content-type" "content-digest")
```

**Full request binding in response:**
```
("@status" "content-type" "@method";req "@authority";req)
```

The `created` and `keyid` parameters in the signature metadata are also important: `created` enables freshness checking, and `keyid` tells the verifier which key to use.
