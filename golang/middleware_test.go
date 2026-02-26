package httpsig

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyMiddlewareAcceptsValidSignature(t *testing.T) {
	pub, priv := generateEd25519Keys(t)
	signingKey := NewEd25519SigningKey("mw-key", priv)
	verifyingKey := NewEd25519VerifyingKey("mw-key", pub)

	provider := KeyProvider(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "mw-key" {
			return verifyingKey, nil
		}
		return nil, ErrKeyNotFound
	})

	handler := &VerifyMiddleware{
		Provider: provider,
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := VerifyResultFromContext(r.Context())
		if result == nil {
			t.Error("expected VerifyResult in context")
			http.Error(w, "no result", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("keyId=" + result.KeyID))
	})

	server := httptest.NewServer(handler.Wrap(inner))
	defer server.Close()

	// Sign a request and send it
	req, _ := http.NewRequest("POST", server.URL+"/resource", strings.NewReader("body"))
	req.Header.Set("Content-Type", "text/plain")

	msg := &RequestMessage{Req: req}
	result, err := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{
			Component("@method"),
			Component("@path"),
			Component("@authority"),
		},
		KeyID:   "mw-key",
		Created: Int64Ptr(time.Now().Unix()),
	}, signingKey, nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Signature-Input", SignatureInputHeader(result))
	req.Header.Set("Signature", SignatureHeader(result))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "keyId=mw-key" {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestVerifyMiddlewareRejectsNoSignature(t *testing.T) {
	pub, _ := generateEd25519Keys(t)
	verifyingKey := NewEd25519VerifyingKey("mw-key", pub)

	mw := RequireSignature(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		return verifyingKey, nil
	}, nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for unsigned requests")
	})

	server := httptest.NewServer(mw(inner))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestVerifyMiddlewareRejectsInvalidSignature(t *testing.T) {
	_, priv := generateEd25519Keys(t)
	signingKey := NewEd25519SigningKey("bad-key", priv)

	// Verify with a different key
	otherPub, _ := generateEd25519Keys(t)
	verifyingKey := NewEd25519VerifyingKey("bad-key", otherPub)

	mw := RequireSignature(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		return verifyingKey, nil
	}, nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for invalid signatures")
	})

	server := httptest.NewServer(mw(inner))
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/test", nil)
	msg := &RequestMessage{Req: req}
	result, _ := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "bad-key",
		Created:    Int64Ptr(time.Now().Unix()),
	}, signingKey, nil)

	req.Header.Set("Signature-Input", SignatureInputHeader(result))
	req.Header.Set("Signature", SignatureHeader(result))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestVerifyMiddlewareRejectsExpired(t *testing.T) {
	pub, priv := generateEd25519Keys(t)
	signingKey := NewEd25519SigningKey("exp-key", priv)
	verifyingKey := NewEd25519VerifyingKey("exp-key", pub)

	mw := RequireSignature(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		return verifyingKey, nil
	}, &VerifyOptions{
		MaxAge: 1 * time.Minute,
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for expired signatures")
	})

	server := httptest.NewServer(mw(inner))
	defer server.Close()

	// Sign with a created timestamp 10 minutes ago
	oldTime := time.Now().Add(-10 * time.Minute).Unix()
	req, _ := http.NewRequest("GET", server.URL+"/test", nil)
	msg := &RequestMessage{Req: req}
	result, _ := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "exp-key",
		Created:    Int64Ptr(oldTime),
	}, signingKey, nil)

	req.Header.Set("Signature-Input", SignatureInputHeader(result))
	req.Header.Set("Signature", SignatureHeader(result))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestVerifyMiddlewareCustomOnError(t *testing.T) {
	pub, _ := generateEd25519Keys(t)
	verifyingKey := NewEd25519VerifyingKey("key", pub)

	var capturedErr error
	handler := &VerifyMiddleware{
		Provider: func(keyID string, alg Algorithm) (VerifyingKey, error) {
			return verifyingKey, nil
		},
		OnError: func(w http.ResponseWriter, r *http.Request, err error) {
			capturedErr = err
			http.Error(w, "custom: "+err.Error(), http.StatusForbidden)
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	})

	server := httptest.NewServer(handler.Wrap(inner))
	defer server.Close()

	resp, err := http.Get(server.URL + "/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	if capturedErr == nil {
		t.Fatal("expected OnError to capture the error")
	}
}

func TestVerifyMiddlewareRequiredComponents(t *testing.T) {
	pub, priv := generateEd25519Keys(t)
	signingKey := NewEd25519SigningKey("comp-key", priv)
	verifyingKey := NewEd25519VerifyingKey("comp-key", pub)

	// Require @method and content-type, but we'll only sign @method
	mw := RequireSignature(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		return verifyingKey, nil
	}, &VerifyOptions{
		RequiredComponents: []ComponentIdentifier{
			Component("@method"),
			Component("content-type"),
		},
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called when required components are missing")
	})

	server := httptest.NewServer(mw(inner))
	defer server.Close()

	req, _ := http.NewRequest("POST", server.URL+"/test", strings.NewReader("data"))
	req.Header.Set("Content-Type", "text/plain")

	// Only sign @method (missing content-type)
	msg := &RequestMessage{Req: req}
	result, _ := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "comp-key",
		Created:    Int64Ptr(time.Now().Unix()),
	}, signingKey, nil)

	req.Header.Set("Signature-Input", SignatureInputHeader(result))
	req.Header.Set("Signature", SignatureHeader(result))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestTransportAndMiddlewareRoundTrip(t *testing.T) {
	pub, priv := generateEd25519Keys(t)
	signingKey := NewEd25519SigningKey("rt-key", priv)
	verifyingKey := NewEd25519VerifyingKey("rt-key", pub)

	// Server uses VerifyMiddleware
	mw := RequireSignature(func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "rt-key" {
			return verifyingKey, nil
		}
		return nil, ErrKeyNotFound
	}, &VerifyOptions{
		RequiredComponents: []ComponentIdentifier{
			Component("@method"),
			Component("@path"),
			Component("@authority"),
		},
		MaxAge: 5 * time.Minute,
	})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := VerifyResultFromContext(r.Context())
		w.Write([]byte("ok:" + result.KeyID))
	})

	server := httptest.NewServer(mw(inner))
	defer server.Close()

	// Client uses Transport
	client := &http.Client{
		Transport: &Transport{
			Base: http.DefaultTransport,
			Key:  signingKey,
		},
	}

	resp, err := client.Get(server.URL + "/api/resource")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok:rt-key" {
		t.Fatalf("unexpected body: %s", body)
	}
}
