package httpsig

import (
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func generateEd25519Keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestTransportSignsRequests(t *testing.T) {
	pub, priv := generateEd25519Keys(t)
	signingKey := NewEd25519SigningKey("test-key", priv)
	verifyingKey := NewEd25519VerifyingKey("test-key", pub)

	// Server that verifies the signature
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := &RequestMessage{Req: r}
		result, err := VerifyMessage(msg, func(keyID string, alg Algorithm) (VerifyingKey, error) {
			if keyID == "test-key" {
				return verifyingKey, nil
			}
			return nil, ErrKeyNotFound
		}, nil, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("verified:" + result.KeyID))
	}))
	defer server.Close()

	transport := &Transport{
		Base: http.DefaultTransport,
		Key:  signingKey,
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL + "/test")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "verified:test-key" {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestTransportCustomParams(t *testing.T) {
	pub, priv := generateEd25519Keys(t)
	signingKey := NewEd25519SigningKey("custom-key", priv)
	verifyingKey := NewEd25519VerifyingKey("custom-key", pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := &RequestMessage{Req: r}
		result, err := VerifyMessage(msg, func(keyID string, alg Algorithm) (VerifyingKey, error) {
			return verifyingKey, nil
		}, &VerifyOptions{
			RequiredComponents: []ComponentIdentifier{
				Component("@method"),
				Component("@authority"),
				Component("content-type"),
			},
		}, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(result.Label))
	}))
	defer server.Close()

	now := time.Now().Unix()
	transport := &Transport{
		Base:  http.DefaultTransport,
		Key:   signingKey,
		Label: "my-sig",
		Params: func(req *http.Request) SignatureParameters {
			return SignatureParameters{
				Components: []ComponentIdentifier{
					Component("@method"),
					Component("@authority"),
					Component("content-type"),
				},
				KeyID:   "custom-key",
				Created: Int64Ptr(now),
			}
		},
	}
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest("POST", server.URL+"/api", strings.NewReader("hello"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "my-sig" {
		t.Fatalf("expected label 'my-sig', got %q", body)
	}
}
