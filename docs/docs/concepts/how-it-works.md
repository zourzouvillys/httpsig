---
sidebar_position: 1
---

# How It Works

HTTP Message Signatures (RFC 9421) provide a mechanism to create, encode, and verify digital signatures or MACs over components of an HTTP message.

## The Signature Flow

Signing and verification follow a straightforward process:

```
Sender                                    Receiver
  |                                          |
  |  1. Build signature base from            |
  |     selected HTTP components             |
  |                                          |
  |  2. Sign the base with private key       |
  |                                          |
  |  3. Add Signature-Input and              |
  |     Signature headers                    |
  |                                          |
  |  --------- HTTP Message ----------->     |
  |                                          |
  |     4. Parse Signature-Input header      |
  |                                          |
  |     5. Reconstruct the signature base    |
  |        from the same components          |
  |                                          |
  |     6. Verify signature with public key  |
  |                                          |
```

## Signature Base

The signature base is a byte string constructed from the HTTP message components that the signer wants to protect. It is deterministic: given the same message and the same set of components, any implementation must produce the same signature base.

A signature base looks like this:

```
"@method": POST
"@path": /api/resource
"@authority": example.com
"content-type": application/json
"@signature-params": ("@method" "@path" "@authority" "content-type");created=1730000000;keyid="my-key-id"
```

Each line is a component identifier (quoted) followed by a colon, a space, and the component value. The last line is always `@signature-params`, which is the serialized inner list of all covered components plus the signature metadata parameters.

This base is then signed with the private key to produce the raw signature bytes.

## HTTP Headers

Two headers carry the signature on the wire:

**Signature-Input** declares what was signed and how:

```
Signature-Input: sig1=("@method" "@path" "@authority" "content-type");created=1730000000;keyid="my-key-id"
```

**Signature** carries the cryptographic signature value (base64-encoded in Structured Field Values binary format):

```
Signature: sig1=:dGhlIHNpZ25hdHVyZSBieXRlcw==:
```

Both headers use the Structured Field Values (RFC 8941) dictionary format. The key (`sig1` above) is the signature label, and a message can carry multiple signatures with different labels.

## Multiple Signatures

A single message can carry multiple independent signatures. Each one gets a unique label:

```
Signature-Input: sig1=("@method" "@authority");keyid="client-key";created=1730000000,
                 sig2=("@method" "@authority" "content-digest");keyid="audit-key";created=1730000000
Signature: sig1=:abc123...:, sig2=:def456...:
```

This is useful when different parties need to sign the same message for different purposes (authentication, audit trail, etc.).

## Request vs. Response Signatures

Signatures can cover both requests and responses:

- **Request signatures**: sign components of the outgoing request (`@method`, `@path`, `@authority`, headers, etc.)
- **Response signatures**: sign components of the response (`@status`, response headers), and can also include request components using the `;req` flag

Response signatures that include request-bound components ensure that the response is tied to a specific request.

## Structured Field Values

RFC 9421 relies heavily on Structured Field Values (RFC 8941) for serialization. All httpsig implementations include a built-in SFV parser and serializer to handle the dictionary, inner list, and parameter formats used in signature headers.
