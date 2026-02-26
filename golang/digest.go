package httpsig

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
)

// DigestAlgorithm identifies a digest algorithm for Content-Digest (RFC 9530).
type DigestAlgorithm string

const (
	DigestSHA256 DigestAlgorithm = "sha-256"
	DigestSHA512 DigestAlgorithm = "sha-512"
)

// ContentDigest computes a Content-Digest header value per RFC 9530.
func ContentDigest(body []byte, alg DigestAlgorithm) (string, error) {
	var h hash.Hash
	switch alg {
	case DigestSHA256:
		h = sha256.New()
	case DigestSHA512:
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported digest algorithm: %s", alg)
	}
	h.Write(body)
	digest := h.Sum(nil)
	return fmt.Sprintf("%s=:%s:", alg, base64.StdEncoding.EncodeToString(digest)), nil
}

// VerifyContentDigest checks that a Content-Digest header value matches the body.
func VerifyContentDigest(body []byte, headerValue string) (bool, error) {
	// Parse all digest values from the header
	// Format: sha-256=:base64:, sha-512=:base64:
	parts := strings.Split(headerValue, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		eqIdx := strings.Index(part, "=:")
		if eqIdx < 0 {
			continue
		}
		algStr := strings.TrimSpace(part[:eqIdx])
		rest := part[eqIdx+2:]
		colonIdx := strings.LastIndex(rest, ":")
		if colonIdx < 0 {
			continue
		}
		b64 := rest[:colonIdx]
		expected, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			continue
		}

		alg := DigestAlgorithm(algStr)
		var h hash.Hash
		switch alg {
		case DigestSHA256:
			h = sha256.New()
		case DigestSHA512:
			h = sha512.New()
		default:
			continue
		}
		h.Write(body)
		actual := h.Sum(nil)

		if len(actual) != len(expected) {
			return false, nil
		}
		match := true
		for i := range actual {
			if actual[i] != expected[i] {
				match = false
				break
			}
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}
