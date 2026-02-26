package com.zourzouvillys.httpsig;

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

    private static final PSSParameterSpec PSS_PARAMS = new PSSParameterSpec(
        "SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1
    );

    static byte[] rsaPssSign(PrivateKey key, byte[] data) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance("RSASSA-PSS");
            sig.setParameter(PSS_PARAMS);
            sig.initSign(key);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("RSA-PSS sign failed", e);
        }
    }

    static boolean rsaPssVerify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance("RSASSA-PSS");
            sig.setParameter(PSS_PARAMS);
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("RSA-PSS verify failed", e);
        }
    }

    // ---- ECDSA P-256 SHA-256 ----
    // RFC 9421 requires raw r||s (64 bytes). Java 15+ has SHA256withECDSAinP1363Format
    // which produces this format directly.

    private static final String ECDSA_P1363 = "SHA256withECDSAinP1363Format";

    static byte[] ecdsaSign(PrivateKey key, byte[] data) throws HttpSigException {
        try {
            Signature sig = Signature.getInstance(ECDSA_P1363);
            sig.initSign(key);
            sig.update(data);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("ECDSA sign failed", e);
        }
    }

    static boolean ecdsaVerify(PublicKey key, byte[] data, byte[] signature) throws HttpSigException {
        try {
            // the signature should be exactly 64 bytes (r||s, 32 each)
            if (signature.length != 64) {
                return false;
            }
            Signature sig = Signature.getInstance(ECDSA_P1363);
            sig.initVerify(key);
            sig.update(data);
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("ECDSA verify failed", e);
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

    static byte[] hmacSign(byte[] secret, byte[] data) throws HttpSigException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new HttpSigException("HMAC-SHA256 sign failed", e);
        }
    }

    static boolean hmacVerify(byte[] secret, byte[] data, byte[] signature) throws HttpSigException {
        byte[] expected = hmacSign(secret, data);
        return MessageDigest.isEqual(expected, signature);
    }
}
