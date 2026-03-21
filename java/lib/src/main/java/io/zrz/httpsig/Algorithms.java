package io.zrz.httpsig;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Low-level crypto operations for each RFC 9421 algorithm.
 *
 * Not public API, just the plumbing that {@link Keys} delegates to.
 */
final class Algorithms {

    private Algorithms() {}

    // ---- RSA-PSS-SHA512 ----

    private static final PSSParameterSpec PSS_SHA512_PARAMS = new PSSParameterSpec(
        "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1
    );

    static byte[] rsaPssSha512Sign(PrivateKey key, byte[] data) throws HttpSigException {
        return rsaPssSign(key, data, PSS_SHA512_PARAMS, "RSA-PSS-SHA512");
    }

    static boolean rsaPssSha512Verify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        return rsaPssVerify(key, data, signature, PSS_SHA512_PARAMS, "RSA-PSS-SHA512");
    }

    // ---- RSA-PSS-SHA256 ----

    private static final PSSParameterSpec PSS_SHA256_PARAMS = new PSSParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1
    );

    static byte[] rsaPssSha256Sign(PrivateKey key, byte[] data) throws HttpSigException {
        return rsaPssSign(key, data, PSS_SHA256_PARAMS, "RSA-PSS-SHA256");
    }

    static boolean rsaPssSha256Verify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        return rsaPssVerify(key, data, signature, PSS_SHA256_PARAMS, "RSA-PSS-SHA256");
    }

    // ---- RSA-PSS-SHA384 ----

    private static final PSSParameterSpec PSS_SHA384_PARAMS = new PSSParameterSpec(
        "SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1
    );

    static byte[] rsaPssSha384Sign(PrivateKey key, byte[] data) throws HttpSigException {
        return rsaPssSign(key, data, PSS_SHA384_PARAMS, "RSA-PSS-SHA384");
    }

    static boolean rsaPssSha384Verify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        return rsaPssVerify(key, data, signature, PSS_SHA384_PARAMS, "RSA-PSS-SHA384");
    }

    // ---- RSA-PSS common ----

    private static byte[] rsaPssSign(PrivateKey key, byte[] data, PSSParameterSpec pssParams, String label) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance("RSASSA-PSS");
            sig.setParameter(pssParams);
            sig.initSign(key);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new HttpSigException(label + " sign failed", e);
        }
    }

    private static boolean rsaPssVerify(PublicKey key, byte[] data, byte[] signature, PSSParameterSpec pssParams, String label) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance("RSASSA-PSS");
            sig.setParameter(pssParams);
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new HttpSigException(label + " verify failed", e);
        }
    }

    // ---- RSA PKCS1v1.5 SHA-256 ----

    static byte[] rsaV15Sha256Sign(PrivateKey key, byte[] data) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(key);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("RSA-v1_5-SHA256 sign failed", e);
        }
    }

    static boolean rsaV15Sha256Verify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("RSA-v1_5-SHA256 verify failed", e);
        }
    }

    // ---- ECDSA P-256 SHA-256 ----
    // RFC 9421 requires raw r||s format. Java 15+ has *inP1363Format JCA names.

    static byte[] ecdsaP256Sign(PrivateKey key, byte[] data) throws HttpSigException {
        return ecdsaSign(key, data, "SHA256withECDSAinP1363Format", "ECDSA-P256");
    }

    static boolean ecdsaP256Verify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        // r||s, 32 each = 64 bytes
        return ecdsaVerify(key, data, signature, "SHA256withECDSAinP1363Format", 64, "ECDSA-P256");
    }

    // ---- ECDSA P-384 SHA-384 ----

    static byte[] ecdsaP384Sign(PrivateKey key, byte[] data) throws HttpSigException {
        return ecdsaSign(key, data, "SHA384withECDSAinP1363Format", "ECDSA-P384");
    }

    static boolean ecdsaP384Verify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        // r||s, 48 each = 96 bytes
        return ecdsaVerify(key, data, signature, "SHA384withECDSAinP1363Format", 96, "ECDSA-P384");
    }

    // ---- ECDSA P-521 SHA-512 ----

    static byte[] ecdsaP521Sign(PrivateKey key, byte[] data) throws HttpSigException {
        return ecdsaSign(key, data, "SHA512withECDSAinP1363Format", "ECDSA-P521");
    }

    static boolean ecdsaP521Verify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        // r||s, 66 each = 132 bytes
        return ecdsaVerify(key, data, signature, "SHA512withECDSAinP1363Format", 132, "ECDSA-P521");
    }

    // ---- ECDSA common ----

    private static byte[] ecdsaSign(PrivateKey key, byte[] data, String jcaAlg, String label) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance(jcaAlg);
            sig.initSign(key);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new HttpSigException(label + " sign failed", e);
        }
    }

    private static boolean ecdsaVerify(PublicKey key, byte[] data, byte[] signature, String jcaAlg, int expectedLen, String label) throws HttpSigException {
        try {
            if (signature.length != expectedLen) {
                return false;
            }
            Signature sig = Signature.getInstance(jcaAlg);
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new HttpSigException(label + " verify failed", e);
        }
    }

    // ---- Ed25519 ----

    static byte[] ed25519Sign(PrivateKey key, byte[] data) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(key);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("Ed25519 sign failed", e);
        }
    }

    static boolean ed25519Verify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("Ed25519 verify failed", e);
        }
    }

    // ---- HMAC-SHA256 ----

    static byte[] hmacSha256Sign(byte[] secret, byte[] data) throws HttpSigException {
        return hmacSign(secret, data, "HmacSHA256");
    }

    static boolean hmacSha256Verify(byte[] secret, byte[] data, byte[] signature) throws HttpSigException {
        return hmacVerify(secret, data, signature, "HmacSHA256");
    }

    // ---- HMAC-SHA384 ----

    static byte[] hmacSha384Sign(byte[] secret, byte[] data) throws HttpSigException {
        return hmacSign(secret, data, "HmacSHA384");
    }

    static boolean hmacSha384Verify(byte[] secret, byte[] data, byte[] signature) throws HttpSigException {
        return hmacVerify(secret, data, signature, "HmacSHA384");
    }

    // ---- HMAC-SHA512 ----

    static byte[] hmacSha512Sign(byte[] secret, byte[] data) throws HttpSigException {
        return hmacSign(secret, data, "HmacSHA512");
    }

    static boolean hmacSha512Verify(byte[] secret, byte[] data, byte[] signature) throws HttpSigException {
        return hmacVerify(secret, data, signature, "HmacSHA512");
    }

    // ---- HMAC common ----

    private static byte[] hmacSign(byte[] secret, byte[] data, String jcaAlg) throws HttpSigException {
        try {
            Mac mac = Mac.getInstance(jcaAlg);
            mac.init(new SecretKeySpec(secret, jcaAlg));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new HttpSigException(jcaAlg + " sign failed", e);
        }
    }

    private static boolean hmacVerify(byte[] secret, byte[] data, byte[] signature, String jcaAlg) throws HttpSigException {
        byte[] expected = hmacSign(secret, data, jcaAlg);
        return MessageDigest.isEqual(expected, signature);
    }
}
