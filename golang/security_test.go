package httpsig

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestMultiValueHeaderJoining verifies that Signature-Input and Signature
// headers split across multiple header fields are correctly joined with ", ".
// Regression: joinHeaderValues previously dropped all but the first value.
func TestMultiValueHeaderJoining(t *testing.T) {
	secret := []byte("regression-test-secret-for-multi-value-headers")
	key := NewHMACSHA256Key("mv-key", secret)

	provider := KeyProvider(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "mv-key" {
			return key, nil
		}
		return nil, ErrKeyNotFound
	})

	msg := &RawMessage{
		IsReq:     true,
		Meth:      "POST",
		TargetURI: mustParseURL(t, "https://example.com/api"),
		Headers:   http.Header{},
	}
	msg.Headers.Set("Content-Type", "application/json")

	now := time.Now().Unix()

	// Sign two separate signatures on the same message.
	result1, err := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "mv-key",
		Created:    Int64Ptr(now),
	}, key, nil)
	if err != nil {
		t.Fatalf("SignMessage sig1: %v", err)
	}

	result2, err := SignMessage(msg, "sig2", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method"), Component("content-type")},
		KeyID:      "mv-key",
		Created:    Int64Ptr(now),
	}, key, nil)
	if err != nil {
		t.Fatalf("SignMessage sig2: %v", err)
	}

	// Build the single-value form that works (sanity check).
	singleSigInput := SignatureInputHeader(result1, result2)
	singleSig := SignatureHeader(result1, result2)

	sanityMsg := cloneRawMessage(msg)
	sanityMsg.Headers.Set("Signature-Input", singleSigInput)
	sanityMsg.Headers.Set("Signature", singleSig)

	if _, err := VerifyMessage(sanityMsg, provider, nil, nil); err != nil {
		t.Fatalf("sanity check (single header) failed: %v", err)
	}

	// Now split into separate header values, simulating multiple header fields
	// arriving from different proxies or middleware.
	splitSigInput1 := SignatureInputHeader(result1)
	splitSigInput2 := SignatureInputHeader(result2)
	splitSig1 := SignatureHeader(result1)
	splitSig2 := SignatureHeader(result2)

	splitMsg := cloneRawMessage(msg)
	splitMsg.Headers.Set("Signature-Input", splitSigInput1)
	splitMsg.Headers.Add("Signature-Input", splitSigInput2)
	splitMsg.Headers.Set("Signature", splitSig1)
	splitMsg.Headers.Add("Signature", splitSig2)

	// This is the regression: if joinHeaderValues only took the first value,
	// sig2 would be invisible and verification of sig2 would fail.
	res, err := VerifyMessage(splitMsg, provider, nil, nil)
	if err != nil {
		t.Fatalf("multi-value header verification failed: %v", err)
	}
	if res.Label != "sig1" && res.Label != "sig2" {
		t.Fatalf("unexpected label: %s", res.Label)
	}

	// Explicitly verify sig2 is reachable when split across headers.
	res2, err := VerifyMessage(splitMsg, provider, &VerifyOptions{RequiredLabel: "sig2"}, nil)
	if err != nil {
		t.Fatalf("sig2 verification failed with split headers: %v", err)
	}
	if res2.Label != "sig2" {
		t.Fatalf("expected label sig2, got %s", res2.Label)
	}
}

// TestFutureDatedSignatureRejection verifies that MaxClockSkew correctly
// rejects signatures with a created time too far in the future, and that
// a zero MaxClockSkew (the default) opts out of the check entirely.
func TestFutureDatedSignatureRejection(t *testing.T) {
	secret := []byte("regression-test-secret-for-future-dating")
	key := NewHMACSHA256Key("future-key", secret)

	provider := KeyProvider(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "future-key" {
			return key, nil
		}
		return nil, ErrKeyNotFound
	})

	futureCreated := time.Now().Add(1 * time.Hour).Unix()

	msg := &RawMessage{
		IsReq:     true,
		Meth:      "GET",
		TargetURI: mustParseURL(t, "https://example.com/clock-test"),
		Headers:   http.Header{},
	}

	result, err := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "future-key",
		Created:    Int64Ptr(futureCreated),
	}, key, nil)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	signedMsg := cloneRawMessage(msg)
	signedMsg.Headers.Set("Signature-Input", SignatureInputHeader(result))
	signedMsg.Headers.Set("Signature", SignatureHeader(result))

	t.Run("rejected_with_tight_skew", func(t *testing.T) {
		_, err := VerifyMessage(signedMsg, provider, &VerifyOptions{
			MaxClockSkew: 30 * time.Second,
		}, nil)
		if err == nil {
			t.Fatal("expected verification to fail for future-dated signature with tight clock skew")
		}
	})

	t.Run("accepted_with_generous_skew", func(t *testing.T) {
		_, err := VerifyMessage(signedMsg, provider, &VerifyOptions{
			MaxClockSkew: 2 * time.Hour,
		}, nil)
		if err != nil {
			t.Fatalf("expected verification to succeed with generous clock skew, got: %v", err)
		}
	})

	t.Run("accepted_with_zero_skew_opt_in", func(t *testing.T) {
		// Zero MaxClockSkew means the check is disabled (opt-in behavior).
		_, err := VerifyMessage(signedMsg, provider, &VerifyOptions{
			MaxClockSkew: 0,
		}, nil)
		if err != nil {
			t.Fatalf("expected verification to succeed with zero MaxClockSkew (opt-in disabled), got: %v", err)
		}
	})

	t.Run("accepted_with_nil_opts", func(t *testing.T) {
		// nil opts should also skip the future-dating check.
		_, err := VerifyMessage(signedMsg, provider, nil, nil)
		if err != nil {
			t.Fatalf("expected verification to succeed with nil opts, got: %v", err)
		}
	})
}

// TestAlgorithmMismatchRejection verifies that when the Signature-Input
// claims a different algorithm than the key actually uses, verification
// fails. This prevents an attacker from signing with a weak algorithm
// while claiming a strong one.
func TestAlgorithmMismatchRejection(t *testing.T) {
	secret := []byte("regression-test-secret-for-alg-mismatch")
	key := NewHMACSHA256Key("alg-key", secret)

	// The provider always returns the HMAC key regardless of what algorithm
	// is claimed. The verifier must reject the mismatch.
	provider := KeyProvider(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "alg-key" {
			return key, nil
		}
		return nil, ErrKeyNotFound
	})

	now := time.Now().Unix()
	msg := &RawMessage{
		IsReq:     true,
		Meth:      "GET",
		TargetURI: mustParseURL(t, "https://example.com/alg-test"),
		Headers:   http.Header{},
	}

	// Sign normally with HMAC, including alg in the params so it appears
	// in the serialized Signature-Input.
	result, err := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "alg-key",
		Algorithm:  AlgorithmHMACSHA256,
		Created:    Int64Ptr(now),
	}, key, nil)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	t.Run("honest_alg_succeeds", func(t *testing.T) {
		honest := cloneRawMessage(msg)
		honest.Headers.Set("Signature-Input", SignatureInputHeader(result))
		honest.Headers.Set("Signature", SignatureHeader(result))

		_, err := VerifyMessage(honest, provider, nil, nil)
		if err != nil {
			t.Fatalf("expected honest signature to verify, got: %v", err)
		}
	})

	t.Run("tampered_alg_fails", func(t *testing.T) {
		// Tamper: replace alg="hmac-sha256" with alg="ed25519" in the
		// Signature-Input header. The signature bytes stay the same
		// (they're HMAC), but the input now claims ed25519.
		sigInput := SignatureInputHeader(result)
		tampered := strings.Replace(sigInput, `alg="hmac-sha256"`, `alg="ed25519"`, 1)
		if tampered == sigInput {
			t.Fatal("tamper failed: alg string not found in Signature-Input")
		}

		tamperedMsg := cloneRawMessage(msg)
		tamperedMsg.Headers.Set("Signature-Input", tampered)
		tamperedMsg.Headers.Set("Signature", SignatureHeader(result))

		_, err := VerifyMessage(tamperedMsg, provider, nil, nil)
		if err == nil {
			t.Fatal("expected verification to fail when alg claim doesn't match key algorithm")
		}
	})

	t.Run("tampered_alg_also_invalidates_sig_base", func(t *testing.T) {
		// Even if we pretended the key matched, changing the alg in the
		// Signature-Input changes the signature base, so the HMAC itself
		// would no longer verify. This is a defense-in-depth check.
		sigInput := SignatureInputHeader(result)
		tampered := strings.Replace(sigInput, `alg="hmac-sha256"`, `alg="hmac-sha256-tampered"`, 1)

		tamperedMsg := cloneRawMessage(msg)
		tamperedMsg.Headers.Set("Signature-Input", tampered)
		tamperedMsg.Headers.Set("Signature", SignatureHeader(result))

		_, err := VerifyMessage(tamperedMsg, provider, nil, nil)
		if err == nil {
			t.Fatal("expected verification to fail with mutated alg value")
		}
	})
}

// --- helpers ---

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return u
}

func cloneRawMessage(orig *RawMessage) *RawMessage {
	h := make(http.Header)
	for k, vs := range orig.Headers {
		h[k] = append([]string(nil), vs...)
	}
	return &RawMessage{
		IsReq:     orig.IsReq,
		Meth:      orig.Meth,
		TargetURI: orig.TargetURI,
		Status:    orig.Status,
		Headers:   h,
	}
}
