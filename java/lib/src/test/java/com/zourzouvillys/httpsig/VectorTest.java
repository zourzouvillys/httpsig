package com.zourzouvillys.httpsig;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Loads the shared RFC 9421 test vectors from testdata/vectors/ and validates:
 * - Signature base construction matches expected bytes
 * - Deterministic algorithms produce the exact expected signature
 * - All signatures round-trip through sign/verify
 * - Pre-computed verify-only signatures verify correctly
 */
class VectorTest {

    private static final Path TESTDATA = Path.of("../../testdata");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TestFactory
    Stream<DynamicTest> signatureBaseTests() throws Exception {
        return loadVectors().map(v ->
            DynamicTest.dynamicTest(v.id + " - signature base", () -> {
                var msg = buildMessage(v.message);
                var reqMsg = v.requestMessage != null ? buildMessage(v.requestMessage) : null;
                var params = buildParams(v);
                var base = SignatureBase.build(msg, params, reqMsg);
                assertEquals(v.expectedBase, new String(base.base(), StandardCharsets.UTF_8));
            })
        );
    }

    @TestFactory
    Stream<DynamicTest> signatureInputTests() throws Exception {
        return loadVectors().map(v ->
            DynamicTest.dynamicTest(v.id + " - signature input", () -> {
                var params = buildParams(v);
                String sigInput = SignatureBase.buildSignatureInput(params);
                // expectedSignatureInput is "label=input", strip the label
                String expected = v.expectedSignatureInput.substring(v.expectedSignatureInput.indexOf('=') + 1);
                assertEquals(expected, sigInput);
            })
        );
    }

    @TestFactory
    Stream<DynamicTest> deterministicSignatureTests() throws Exception {
        return loadVectors()
            .filter(v -> v.deterministic)
            .map(v -> DynamicTest.dynamicTest(v.id + " - deterministic signature", () -> {
                var msg = buildMessage(v.message);
                var reqMsg = v.requestMessage != null ? buildMessage(v.requestMessage) : null;
                var params = buildParams(v);
                var signingKey = loadSigningKey(v);

                var result = Signer.sign(msg, v.label, params, signingKey, reqMsg);
                String actual = Base64.getEncoder().encodeToString(result.signature());
                assertEquals(v.expectedSignature, actual);
            }));
    }

    @TestFactory
    Stream<DynamicTest> verifyPrecomputedTests() throws Exception {
        return loadVectors()
            .filter(v -> v.verifyOnlySignature != null)
            .map(v -> DynamicTest.dynamicTest(v.id + " - verify precomputed", () -> {
                var msg = buildMessage(v.message);
                var reqMsg = v.requestMessage != null ? buildMessage(v.requestMessage) : null;
                var verifyingKey = loadVerifyingKey(v);

                // build signed message with precomputed signature
                String sigInputVal = v.expectedSignatureInput.substring(v.expectedSignatureInput.indexOf('=') + 1);
                String sigInputHeader = v.label + "=" + sigInputVal;
                String sigHeader = v.label + "=:" + v.verifyOnlySignature + ":";

                var signedMsg = addSignatureHeaders(v.message, sigInputHeader, sigHeader);
                var result = Verifier.verify(signedMsg, (keyId, alg) -> verifyingKey,
                    Verifier.VerifyOptions.defaults(), reqMsg);

                assertEquals(v.label, result.label());
            }));
    }

    @TestFactory
    Stream<DynamicTest> roundTripTests() throws Exception {
        return loadVectors().map(v ->
            DynamicTest.dynamicTest(v.id + " - round trip", () -> {
                var msg = buildMessage(v.message);
                var reqMsg = v.requestMessage != null ? buildMessage(v.requestMessage) : null;
                var params = buildParams(v);
                var signingKey = loadSigningKey(v);
                var verifyingKey = loadVerifyingKey(v);

                var result = Signer.sign(msg, v.label, params, signingKey, reqMsg);
                String sigInputHeader = Signer.signatureInputHeader(result);
                String sigHeader = Signer.signatureHeader(result);

                var signedMsg = addSignatureHeaders(v.message, sigInputHeader, sigHeader);
                var verifyResult = Verifier.verify(signedMsg, (keyId, alg) -> verifyingKey,
                    Verifier.VerifyOptions.defaults(), reqMsg);

                assertEquals(v.label, verifyResult.label());
                assertEquals(v.keyId, verifyResult.keyId());
            })
        );
    }

    // ---- Vector loading ----

    private Stream<Vector> loadVectors() throws IOException {
        var vectorDir = TESTDATA.resolve("vectors");
        return Files.list(vectorDir)
            .filter(p -> p.toString().endsWith(".json"))
            .sorted()
            .map(p -> {
                try {
                    return parseVector(MAPPER.readTree(p.toFile()));
                } catch (Exception e) {
                    throw new RuntimeException("failed to parse " + p, e);
                }
            });
    }

    private Vector parseVector(JsonNode root) {
        var v = new Vector();
        v.id = root.get("id").asText();
        v.description = root.get("description").asText();
        v.message = root.get("message");
        v.requestMessage = root.has("requestMessage") ? root.get("requestMessage") : null;
        v.expectedBase = root.get("expectedBase").asText();
        v.expectedSignatureInput = root.get("expectedSignatureInput").asText();
        v.deterministic = root.get("deterministic").asBoolean();

        if (root.has("expectedSignature")) {
            v.expectedSignature = root.get("expectedSignature").asText();
        }
        if (root.has("verifyOnlySignature")) {
            v.verifyOnlySignature = root.get("verifyOnlySignature").asText();
        }

        var sp = root.get("signingParams");
        v.label = sp.get("label").asText();
        v.keyId = sp.get("keyId").asText();
        v.algorithm = sp.get("algorithm").asText();
        v.created = sp.has("created") ? sp.get("created").asLong() : null;
        v.nonce = sp.has("nonce") ? sp.get("nonce").asText() : null;
        v.tag = sp.has("tag") ? sp.get("tag").asText() : null;

        v.components = new ArrayList<>();
        for (var comp : sp.get("components")) {
            if (comp.isTextual()) {
                v.components.add(ComponentIdentifier.of(comp.asText()));
            } else {
                String name = comp.get("name").asText();
                Map<String, Object> params = new LinkedHashMap<>();
                var paramsNode = comp.get("params");
                paramsNode.fieldNames().forEachRemaining(k ->
                    params.put(k, paramsNode.get(k).asText())
                );
                v.components.add(ComponentIdentifier.withParams(name, params));
            }
        }

        v.keyFile = root.has("keyFile") ? root.get("keyFile").asText() : null;
        v.pubKeyFile = root.has("pubKeyFile") ? root.get("pubKeyFile").asText() : null;

        return v;
    }

    // ---- Message building ----

    private HttpMessage buildMessage(JsonNode msg) {
        String type = msg.get("type").asText();
        var headersNode = msg.get("headers");

        // headers can have duplicate names (e.g. Accept appears twice)
        Map<String, List<String>> headers = new LinkedHashMap<>();
        if (headersNode != null) {
            for (var entry : headersNode) {
                String name = entry.get(0).asText();
                String value = entry.get(1).asText();
                headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
            }
        }

        if ("request".equals(type)) {
            String method = msg.get("method").asText();
            URI url = URI.create(msg.get("url").asText());
            return RawMessage.request(method, url, headers);
        } else {
            int statusCode = msg.get("statusCode").asInt();
            return RawMessage.response(statusCode, headers);
        }
    }

    private HttpMessage addSignatureHeaders(JsonNode origMsg, String sigInputHeader, String sigHeader) {
        String type = origMsg.get("type").asText();
        var headersNode = origMsg.get("headers");

        Map<String, List<String>> headers = new LinkedHashMap<>();
        if (headersNode != null) {
            for (var entry : headersNode) {
                String name = entry.get(0).asText();
                String value = entry.get(1).asText();
                headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
            }
        }
        headers.put("signature-input", List.of(sigInputHeader));
        headers.put("signature", List.of(sigHeader));

        if ("request".equals(type)) {
            String method = origMsg.get("method").asText();
            URI url = URI.create(origMsg.get("url").asText());
            return RawMessage.request(method, url, headers);
        } else {
            int statusCode = origMsg.get("statusCode").asInt();
            return RawMessage.response(statusCode, headers);
        }
    }

    // ---- Params building ----

    private SignatureParameters buildParams(Vector v) {
        var builder = SignatureParameters.builder();
        for (var comp : v.components) {
            builder.component(comp);
        }
        builder.keyId(v.keyId);
        // note: the "algorithm" field in the vector JSON is for key selection,
        // NOT for the `alg` signature parameter. the RFC test vectors don't
        // include `alg=` in their expected output.
        if (v.created != null) {
            builder.createdEpoch(v.created);
        }
        if (v.nonce != null) {
            builder.nonce(v.nonce);
        }
        if (v.tag != null) {
            builder.tag(v.tag);
        }
        return builder.build();
    }

    // ---- Key loading ----

    private SigningKey loadSigningKey(Vector v) throws Exception {
        Algorithm alg = Algorithm.fromValue(v.algorithm);
        return switch (alg) {
            case HMAC_SHA256 -> {
                byte[] secret = loadHmacSecret();
                yield Keys.hmacSHA256Key(v.keyId, secret);
            }
            case ED25519 -> {
                PrivateKey pk = loadPkcs8PrivateKey(TESTDATA.resolve(v.keyFile), "Ed25519");
                yield Keys.ed25519SigningKey(v.keyId, pk);
            }
            case RSA_PSS_SHA512 -> {
                PrivateKey pk = loadPkcs8PrivateKey(TESTDATA.resolve(v.keyFile), "RSA");
                yield Keys.rsaPSSSigningKey(v.keyId, pk);
            }
            case ECDSA_P256_SHA256 -> {
                PrivateKey pk = loadEcPrivateKey(TESTDATA.resolve(v.keyFile));
                yield Keys.ecdsaP256SigningKey(v.keyId, pk);
            }
        };
    }

    private VerifyingKey loadVerifyingKey(Vector v) throws Exception {
        Algorithm alg = Algorithm.fromValue(v.algorithm);
        return switch (alg) {
            case HMAC_SHA256 -> {
                byte[] secret = loadHmacSecret();
                yield Keys.hmacSHA256Key(v.keyId, secret);
            }
            case ED25519 -> {
                PublicKey pk = loadSpkiPublicKey(TESTDATA.resolve(v.pubKeyFile), "Ed25519");
                yield Keys.ed25519VerifyingKey(v.keyId, pk);
            }
            case RSA_PSS_SHA512 -> {
                PublicKey pk = loadSpkiPublicKey(TESTDATA.resolve(v.pubKeyFile), "RSA");
                yield Keys.rsaPSSVerifyingKey(v.keyId, pk);
            }
            case ECDSA_P256_SHA256 -> {
                PublicKey pk = loadSpkiPublicKey(TESTDATA.resolve(v.pubKeyFile), "EC");
                yield Keys.ecdsaP256VerifyingKey(v.keyId, pk);
            }
        };
    }

    private byte[] loadHmacSecret() throws IOException {
        String b64 = Files.readString(TESTDATA.resolve("keys/hmac-secret.b64")).trim();
        return Base64.getDecoder().decode(b64);
    }

    private PrivateKey loadPkcs8PrivateKey(Path path, String algorithm) throws Exception {
        byte[] der = decodePem(Files.readString(path));
        var spec = new PKCS8EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance(algorithm).generatePrivate(spec);
        } catch (java.security.spec.InvalidKeySpecException e) {
            // the key OID might be RSASSA-PSS while we tried RSA, or vice versa
            if ("RSA".equals(algorithm)) {
                return KeyFactory.getInstance("RSASSA-PSS").generatePrivate(spec);
            }
            throw e;
        }
    }

    private PrivateKey loadEcPrivateKey(Path path, String... ignored) throws Exception {
        String pem = Files.readString(path);
        if (pem.contains("BEGIN EC PRIVATE KEY")) {
            // SEC1 format: convert via OpenSSL-style parsing
            // Java doesn't natively support SEC1, but we can use BouncyCastle
            // or just convert. Since our test keys also work as PKCS#8 with
            // the EC algorithm, let's try the direct approach first.
            // Actually, Java's KeyFactory("EC") can handle PKCS#8 but not SEC1.
            // We need to wrap the SEC1 key in PKCS#8 ASN.1 structure.
            byte[] sec1Der = decodePem(pem);
            byte[] pkcs8Der = wrapEc256Sec1ToPkcs8(sec1Der);
            var spec = new PKCS8EncodedKeySpec(pkcs8Der);
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
        // already PKCS#8
        return loadPkcs8PrivateKey(path, "EC");
    }

    private PublicKey loadSpkiPublicKey(Path path, String algorithm) throws Exception {
        byte[] der = decodePem(Files.readString(path));
        var spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance(algorithm).generatePublic(spec);
    }

    private static byte[] decodePem(String pem) {
        String b64 = pem.replaceAll("-----[A-Z ]+-----", "")
                        .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(b64);
    }

    /**
     * Wraps a SEC1 EC private key in a PKCS#8 envelope for P-256.
     * This is the ASN.1 structure:
     *   SEQUENCE {
     *     INTEGER 0
     *     SEQUENCE { OID ecPublicKey, OID prime256v1 }
     *     OCTET STRING { <sec1-key-bytes> }
     *   }
     */
    private static byte[] wrapEc256Sec1ToPkcs8(byte[] sec1Der) {
        // PKCS#8 header for EC P-256: version=0, algorithm=ecPublicKey, curve=prime256v1
        byte[] prefix = new byte[] {
            0x30, (byte) 0x81, // SEQUENCE, length placeholder
            0x00,              // length byte (will be filled)
            // version INTEGER 0
            0x02, 0x01, 0x00,
            // AlgorithmIdentifier SEQUENCE
            0x30, 0x13,
            // OID 1.2.840.10045.2.1 (ecPublicKey)
            0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01,
            // OID 1.2.840.10045.3.1.7 (prime256v1)
            0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07,
            // OCTET STRING wrapping the SEC1 key
            0x04,
        };

        // calculate lengths
        int octetStringContentLen = sec1Der.length;
        int octetStringHeaderLen = octetStringContentLen < 128 ? 1 : 2;
        int totalSeqContent = 3 + 21 + 1 + octetStringHeaderLen + octetStringContentLen;

        var result = new ArrayList<Byte>();

        // outer SEQUENCE
        result.add((byte) 0x30);
        if (totalSeqContent < 128) {
            result.add((byte) totalSeqContent);
        } else {
            result.add((byte) 0x81);
            result.add((byte) totalSeqContent);
        }

        // version INTEGER 0
        result.add((byte) 0x02); result.add((byte) 0x01); result.add((byte) 0x00);

        // AlgorithmIdentifier
        result.add((byte) 0x30); result.add((byte) 0x13);
        // ecPublicKey OID
        for (byte b : new byte[] {0x06, 0x07, 0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x02, 0x01}) {
            result.add(b);
        }
        // prime256v1 OID
        for (byte b : new byte[] {0x06, 0x08, 0x2a, (byte)0x86, 0x48, (byte)0xce, 0x3d, 0x03, 0x01, 0x07}) {
            result.add(b);
        }

        // OCTET STRING containing SEC1 key
        result.add((byte) 0x04);
        if (octetStringContentLen < 128) {
            result.add((byte) octetStringContentLen);
        } else {
            result.add((byte) 0x81);
            result.add((byte) octetStringContentLen);
        }
        for (byte b : sec1Der) {
            result.add(b);
        }

        byte[] out = new byte[result.size()];
        for (int i = 0; i < result.size(); i++) {
            out[i] = result.get(i);
        }
        return out;
    }

    // ---- Test vector data holder ----

    private static class Vector {
        String id;
        String description;
        JsonNode message;
        JsonNode requestMessage;
        String expectedBase;
        String expectedSignatureInput;
        boolean deterministic;
        String expectedSignature;
        String verifyOnlySignature;
        String label;
        String keyId;
        String algorithm;
        Long created;
        String nonce;
        String tag;
        List<ComponentIdentifier> components;
        String keyFile;
        String pubKeyFile;
    }
}
