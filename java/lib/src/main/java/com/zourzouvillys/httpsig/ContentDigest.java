package com.zourzouvillys.httpsig;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Content-Digest header support per RFC 9530.
 *
 * Computes and verifies digest values for HTTP message bodies,
 * typically used alongside HTTP signatures to bind the body.
 */
public final class ContentDigest {

    private ContentDigest() {}

    /**
     * Digest algorithm identifiers.
     */
    public enum DigestAlgorithm {
        SHA_256("sha-256", "SHA-256"),
        SHA_512("sha-512", "SHA-512");

        private final String sfvName;
        private final String javaName;

        DigestAlgorithm(String sfvName, String javaName) {
            this.sfvName = sfvName;
            this.javaName = javaName;
        }

        /** The name used in the Content-Digest header (e.g. "sha-256"). */
        public String sfvName() { return sfvName; }
    }

    /**
     * Compute a Content-Digest header value for the given body.
     *
     * @return a complete header value, e.g. "sha-256=:base64digest:"
     */
    public static String compute(byte[] body, DigestAlgorithm alg) {
        try {
            MessageDigest md = MessageDigest.getInstance(alg.javaName);
            byte[] digest = md.digest(body);
            String b64 = Base64.getEncoder().encodeToString(digest);
            return alg.sfvName + "=:" + b64 + ":";
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 and SHA-512 are guaranteed to be available in any JVM
            throw new AssertionError("missing digest algorithm: " + alg.javaName, e);
        }
    }

    /**
     * Verify a Content-Digest header value against a body.
     *
     * The header value may contain multiple digest entries (SFV Dictionary).
     * Returns true if at least one recognized algorithm matches.
     *
     * @param body        the message body bytes
     * @param headerValue the Content-Digest header value
     * @return true if verification succeeds
     */
    public static boolean verify(byte[] body, String headerValue) throws HttpSigException {
        var entries = SFV.parseDictionary(headerValue);
        boolean anyChecked = false;
        for (var entry : entries) {
            DigestAlgorithm alg = findAlgorithm(entry.key());
            if (alg == null) {
                continue; // skip unknown algorithms
            }
            anyChecked = true;

            // the value should be an Item containing a byte[]
            byte[] expectedDigest;
            if (entry.value() instanceof SFV.Item item && item.value() instanceof byte[] b) {
                expectedDigest = b;
            } else {
                throw new HttpSigException("invalid digest value for " + entry.key());
            }

            try {
                MessageDigest md = MessageDigest.getInstance(alg.javaName);
                byte[] actual = md.digest(body);
                if (!MessageDigest.isEqual(actual, expectedDigest)) {
                    return false;
                }
            } catch (NoSuchAlgorithmException e) {
                throw new AssertionError("missing digest algorithm: " + alg.javaName, e);
            }
        }
        if (!anyChecked) {
            throw new HttpSigException("no recognized digest algorithm in Content-Digest header");
        }
        return true;
    }

    private static DigestAlgorithm findAlgorithm(String name) {
        for (var alg : DigestAlgorithm.values()) {
            if (alg.sfvName.equals(name)) return alg;
        }
        return null;
    }
}
