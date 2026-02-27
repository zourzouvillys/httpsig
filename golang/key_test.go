package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadTestKeyRSA returns the RSA-PSS private key from testdata.
func loadTestKeyRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "keys", "rsa-pss.priv.pem"))
	if err != nil {
		t.Fatalf("read RSA key: %v", err)
	}
	key, err := ParseRSAPSSPrivateKeyPEM(data)
	if err != nil {
		t.Fatalf("parse RSA key: %v", err)
	}
	return key
}

// loadTestKeyECDSA returns the EC P-256 private key from testdata.
func loadTestKeyECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "keys", "ecc-p256.priv.pem"))
	if err != nil {
		t.Fatalf("read EC key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("failed to decode EC PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse EC key: %v", err)
	}
	return key
}

// loadTestKeyEd25519 returns the Ed25519 private key from testdata.
func loadTestKeyEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "keys", "ed25519.priv.pem"))
	if err != nil {
		t.Fatalf("read Ed25519 key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("failed to decode Ed25519 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse Ed25519 key: %v", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", parsed)
	}
	return key
}

// loadTestHMACSecret returns the HMAC shared secret from testdata.
func loadTestHMACSecret(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "keys", "hmac-secret.b64"))
	if err != nil {
		t.Fatalf("read HMAC secret: %v", err)
	}
	secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("decode HMAC secret: %v", err)
	}
	return secret
}

func TestKeyPairRSA(t *testing.T) {
	key := loadTestKeyRSA(t)

	kp, err := NewKeyPair("rsa-test", key)
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}

	if kp.KeyID() != "rsa-test" {
		t.Errorf("KeyID = %q, want %q", kp.KeyID(), "rsa-test")
	}
	if kp.Algorithm() != AlgorithmRSAPSSSHA512 {
		t.Errorf("Algorithm = %q, want %q", kp.Algorithm(), AlgorithmRSAPSSSHA512)
	}

	data := []byte("RSA-PSS round trip test payload")
	sig, err := kp.Signing.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := kp.Verifying.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("round-trip verification failed")
	}
}

func TestKeyPairECDSA(t *testing.T) {
	key := loadTestKeyECDSA(t)

	kp, err := NewKeyPair("ec-test", key)
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}

	if kp.KeyID() != "ec-test" {
		t.Errorf("KeyID = %q, want %q", kp.KeyID(), "ec-test")
	}
	if kp.Algorithm() != AlgorithmECDSAP256SHA256 {
		t.Errorf("Algorithm = %q, want %q", kp.Algorithm(), AlgorithmECDSAP256SHA256)
	}

	data := []byte("ECDSA P-256 round trip test payload")
	sig, err := kp.Signing.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := kp.Verifying.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("round-trip verification failed")
	}
}

func TestKeyPairEd25519(t *testing.T) {
	key := loadTestKeyEd25519(t)

	kp, err := NewKeyPair("ed-test", key)
	if err != nil {
		t.Fatalf("NewKeyPair: %v", err)
	}

	if kp.KeyID() != "ed-test" {
		t.Errorf("KeyID = %q, want %q", kp.KeyID(), "ed-test")
	}
	if kp.Algorithm() != AlgorithmEd25519 {
		t.Errorf("Algorithm = %q, want %q", kp.Algorithm(), AlgorithmEd25519)
	}

	data := []byte("Ed25519 round trip test payload")
	sig, err := kp.Signing.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := kp.Verifying.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("round-trip verification failed")
	}
}

func TestKeyPairHMAC(t *testing.T) {
	secret := loadTestHMACSecret(t)

	kp := NewHMACKeyPair("hmac-test", secret)

	if kp.KeyID() != "hmac-test" {
		t.Errorf("KeyID = %q, want %q", kp.KeyID(), "hmac-test")
	}
	if kp.Algorithm() != AlgorithmHMACSHA256 {
		t.Errorf("Algorithm = %q, want %q", kp.Algorithm(), AlgorithmHMACSHA256)
	}

	data := []byte("HMAC-SHA256 round trip test payload")
	sig, err := kp.Signing.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := kp.Verifying.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("round-trip verification failed")
	}
}

func TestNewSigningKeyFromSigner(t *testing.T) {
	tests := []struct {
		name    string
		signer  crypto.Signer
		wantAlg Algorithm
	}{
		{"RSA-PSS", loadTestKeyRSA(t), AlgorithmRSAPSSSHA512},
		{"ECDSA-P256", loadTestKeyECDSA(t), AlgorithmECDSAP256SHA256},
		{"Ed25519", loadTestKeyEd25519(t), AlgorithmEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sk, err := NewSigningKeyFromSigner("test-"+tt.name, tt.signer)
			if err != nil {
				t.Fatalf("NewSigningKeyFromSigner: %v", err)
			}
			if sk.Algorithm() != tt.wantAlg {
				t.Errorf("Algorithm = %q, want %q", sk.Algorithm(), tt.wantAlg)
			}
			if sk.KeyID() != "test-"+tt.name {
				t.Errorf("KeyID = %q, want %q", sk.KeyID(), "test-"+tt.name)
			}
		})
	}
}

func TestNewVerifyingKeyFromPublic(t *testing.T) {
	tests := []struct {
		name    string
		pub     crypto.PublicKey
		wantAlg Algorithm
	}{
		{"RSA-PSS", &loadTestKeyRSA(t).PublicKey, AlgorithmRSAPSSSHA512},
		{"ECDSA-P256", &loadTestKeyECDSA(t).PublicKey, AlgorithmECDSAP256SHA256},
		{"Ed25519", loadTestKeyEd25519(t).Public(), AlgorithmEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vk, err := NewVerifyingKeyFromPublic("test-"+tt.name, tt.pub)
			if err != nil {
				t.Fatalf("NewVerifyingKeyFromPublic: %v", err)
			}
			if vk.Algorithm() != tt.wantAlg {
				t.Errorf("Algorithm = %q, want %q", vk.Algorithm(), tt.wantAlg)
			}
			if vk.KeyID() != "test-"+tt.name {
				t.Errorf("KeyID = %q, want %q", vk.KeyID(), "test-"+tt.name)
			}
		})
	}
}

func TestDetectAlgorithmErrors(t *testing.T) {
	// Unsupported EC curve (P-384)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384 key: %v", err)
	}
	_, err = detectAlgorithm(&p384Key.PublicKey)
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("P-384: got err=%v, want ErrInvalidKey", err)
	}

	// Unsupported key type (a string, just to exercise the default branch)
	_, err = detectAlgorithm("not-a-key")
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("string key: got err=%v, want ErrInvalidKey", err)
	}
}

func TestNewKeyPairNonSigner(t *testing.T) {
	// A plain []byte doesn't implement crypto.Signer.
	_, err := NewKeyPair("nope", []byte("not a signer"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("got err=%v, want ErrInvalidKey", err)
	}
}

func TestSigningKeyFromSignerAndVerifyingKeyFromPublicRoundTrip(t *testing.T) {
	// Ensure a key created via auto-detect signing can be verified by auto-detect verifying.
	rsaKey := loadTestKeyRSA(t)

	sk, err := NewSigningKeyFromSigner("rt", rsaKey)
	if err != nil {
		t.Fatalf("NewSigningKeyFromSigner: %v", err)
	}
	vk, err := NewVerifyingKeyFromPublic("rt", &rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("NewVerifyingKeyFromPublic: %v", err)
	}

	data := []byte("cross-constructor round trip")
	sig, err := sk.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	ok, err := vk.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("round-trip verification failed")
	}
}
