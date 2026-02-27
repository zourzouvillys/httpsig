package io.zrz.httpsig;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;

import org.junit.jupiter.api.Test;

class KeyPairTest {

    private static final Path KEYS_DIR = Path.of("../../testdata/keys");

    // --- Auto-detection tests ---

    @Test
    void detectsRsaPss() throws Exception {
        PrivateKey priv = loadPkcs8PrivateKey(KEYS_DIR.resolve("rsa-pss.priv.pem"), "RSA");
        SigningKey sk = Keys.signingKey("rsa-test", priv);
        assertEquals(Algorithm.RSA_PSS_SHA512, sk.algorithm());
        assertEquals("rsa-test", sk.keyId());
    }

    @Test
    void detectsEcdsaP256() throws Exception {
        PrivateKey priv = loadEcPrivateKey(KEYS_DIR.resolve("ecc-p256.priv.pem"));
        SigningKey sk = Keys.signingKey("ec-test", priv);
        assertEquals(Algorithm.ECDSA_P256_SHA256, sk.algorithm());
    }

    @Test
    void detectsEd25519() throws Exception {
        PrivateKey priv = loadPkcs8PrivateKey(KEYS_DIR.resolve("ed25519.priv.pem"), "Ed25519");
        SigningKey sk = Keys.signingKey("ed-test", priv);
        assertEquals(Algorithm.ED25519, sk.algorithm());
    }

    // --- KeyPair round-trip tests ---

    @Test
    void rsaKeyPairRoundTrip() throws Exception {
        PrivateKey priv = loadPkcs8PrivateKey(KEYS_DIR.resolve("rsa-pss.priv.pem"), "RSA");
        PublicKey pub = loadSpkiPublicKey(KEYS_DIR.resolve("rsa-pss.pub.pem"), "RSA");
        io.zrz.httpsig.KeyPair kp = Keys.keyPair("rsa-kp", priv, pub);

        assertEquals("rsa-kp", kp.keyId());
        assertEquals(Algorithm.RSA_PSS_SHA512, kp.algorithm());

        byte[] data = "test data".getBytes();
        byte[] sig = kp.signingKey().sign(data);
        assertTrue(kp.verifyingKey().verify(data, sig));
    }

    @Test
    void ecdsaKeyPairRoundTrip() throws Exception {
        PrivateKey priv = loadEcPrivateKey(KEYS_DIR.resolve("ecc-p256.priv.pem"));
        PublicKey pub = loadSpkiPublicKey(KEYS_DIR.resolve("ecc-p256.pub.pem"), "EC");
        io.zrz.httpsig.KeyPair kp = Keys.keyPair("ec-kp", priv, pub);

        assertEquals(Algorithm.ECDSA_P256_SHA256, kp.algorithm());

        byte[] data = "test data".getBytes();
        byte[] sig = kp.signingKey().sign(data);
        assertTrue(kp.verifyingKey().verify(data, sig));
    }

    @Test
    void ed25519KeyPairRoundTrip() throws Exception {
        PrivateKey priv = loadPkcs8PrivateKey(KEYS_DIR.resolve("ed25519.priv.pem"), "Ed25519");
        PublicKey pub = loadSpkiPublicKey(KEYS_DIR.resolve("ed25519.pub.pem"), "Ed25519");
        io.zrz.httpsig.KeyPair kp = Keys.keyPair("ed-kp", priv, pub);

        assertEquals(Algorithm.ED25519, kp.algorithm());

        byte[] data = "test data".getBytes();
        byte[] sig = kp.signingKey().sign(data);
        assertTrue(kp.verifyingKey().verify(data, sig));
    }

    @Test
    void hmacKeyPairRoundTrip() throws Exception {
        byte[] secret = "super-secret-key-at-least-32-bytes!!".getBytes();
        io.zrz.httpsig.KeyPair kp = Keys.hmacKeyPair("hmac-kp", secret);

        assertEquals(Algorithm.HMAC_SHA256, kp.algorithm());
        assertEquals("hmac-kp", kp.keyId());

        byte[] data = "test data".getBytes();
        byte[] sig = kp.signingKey().sign(data);
        assertTrue(kp.verifyingKey().verify(data, sig));
    }

    @Test
    void jcaKeyPairBridge() throws Exception {
        var keyGen = java.security.KeyPairGenerator.getInstance("Ed25519");
        java.security.KeyPair jcaKp = keyGen.generateKeyPair();
        io.zrz.httpsig.KeyPair kp = Keys.keyPair("jca-ed", jcaKp);

        assertEquals(Algorithm.ED25519, kp.algorithm());

        byte[] data = "test data".getBytes();
        byte[] sig = kp.signingKey().sign(data);
        assertTrue(kp.verifyingKey().verify(data, sig));
    }

    @Test
    void keyPairRejectsIdMismatch() throws Exception {
        PrivateKey priv = loadPkcs8PrivateKey(KEYS_DIR.resolve("ed25519.priv.pem"), "Ed25519");
        PublicKey pub = loadSpkiPublicKey(KEYS_DIR.resolve("ed25519.pub.pem"), "Ed25519");
        SigningKey sk = Keys.ed25519SigningKey("a", priv);
        VerifyingKey vk = Keys.ed25519VerifyingKey("b", pub);
        assertThrows(IllegalArgumentException.class, () -> new io.zrz.httpsig.KeyPair(sk, vk));
    }

    @Test
    void keyPairRejectsAlgorithmMismatch() throws Exception {
        PrivateKey rsaPriv = loadPkcs8PrivateKey(KEYS_DIR.resolve("rsa-pss.priv.pem"), "RSA");
        PublicKey edPub = loadSpkiPublicKey(KEYS_DIR.resolve("ed25519.pub.pem"), "Ed25519");
        SigningKey sk = Keys.rsaPSSSigningKey("same-id", rsaPriv);
        VerifyingKey vk = Keys.ed25519VerifyingKey("same-id", edPub);
        assertThrows(IllegalArgumentException.class, () -> new io.zrz.httpsig.KeyPair(sk, vk));
    }

    @Test
    void keyPairRejectsNullSigningKey() {
        assertThrows(NullPointerException.class, () ->
            new io.zrz.httpsig.KeyPair(null, Keys.ed25519VerifyingKey("x",
                loadSpkiPublicKey(KEYS_DIR.resolve("ed25519.pub.pem"), "Ed25519"))));
    }

    @Test
    void autoDetectRejectsUnsupportedAlgorithm() {
        // DSA keys should be rejected
        assertThrows(IllegalArgumentException.class, () -> {
            var keyGen = java.security.KeyPairGenerator.getInstance("DSA");
            keyGen.initialize(2048);
            java.security.KeyPair dsa = keyGen.generateKeyPair();
            Keys.signingKey("dsa", dsa.getPrivate());
        });
    }

    // ---- Key loading helpers (same patterns as VectorTest) ----

    private static PrivateKey loadPkcs8PrivateKey(Path path, String algorithm) throws Exception {
        byte[] der = decodePem(Files.readString(path));
        var spec = new PKCS8EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance(algorithm).generatePrivate(spec);
        } catch (java.security.spec.InvalidKeySpecException e) {
            if ("RSA".equals(algorithm)) {
                return KeyFactory.getInstance("RSASSA-PSS").generatePrivate(spec);
            }
            throw e;
        }
    }

    private static PrivateKey loadEcPrivateKey(Path path) throws Exception {
        String pem = Files.readString(path);
        if (pem.contains("BEGIN EC PRIVATE KEY")) {
            byte[] sec1Der = decodePem(pem);
            byte[] pkcs8Der = wrapEc256Sec1ToPkcs8(sec1Der);
            return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(pkcs8Der));
        }
        return loadPkcs8PrivateKey(path, "EC");
    }

    private static PublicKey loadSpkiPublicKey(Path path, String algorithm) throws Exception {
        byte[] der = decodePem(Files.readString(path));
        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(der));
    }

    private static byte[] decodePem(String pem) {
        String b64 = pem.replaceAll("-----[A-Z ]+-----", "")
                        .replaceAll("\\s+", "");
        return Base64.getDecoder().decode(b64);
    }

    /**
     * Wraps a SEC1 EC private key in a PKCS#8 envelope for P-256.
     * Lifted from VectorTest to handle variable-length DER encoding correctly.
     */
    private static byte[] wrapEc256Sec1ToPkcs8(byte[] sec1Der) {
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

        // AlgorithmIdentifier SEQUENCE (21 bytes)
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
}
