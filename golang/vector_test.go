package httpsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vectorFile is the JSON structure for a test vector file.
type vectorFile struct {
	ID                     string          `json:"id"`
	Description            string          `json:"description"`
	Message                vectorMessage   `json:"message"`
	RequestMessage         *vectorMessage  `json:"requestMessage,omitempty"`
	SigningParams          vectorSigParams `json:"signingParams"`
	ExpectedBase           string          `json:"expectedBase"`
	ExpectedSignatureInput string          `json:"expectedSignatureInput"`
	ExpectedSignature      string          `json:"expectedSignature,omitempty"`
	VerifyOnlySignature    string          `json:"verifyOnlySignature,omitempty"`
	Deterministic          bool            `json:"deterministic"`
	KeyFile                string          `json:"keyFile,omitempty"`
	PubKeyFile             string          `json:"pubKeyFile,omitempty"`
}

type vectorMessage struct {
	Type       string     `json:"type"`
	Method     string     `json:"method,omitempty"`
	URL        string     `json:"url,omitempty"`
	StatusCode int        `json:"statusCode,omitempty"`
	Headers    [][]string `json:"headers"`
	Body       string     `json:"body,omitempty"`
}

type vectorSigParams struct {
	Label      string `json:"label"`
	Components []any  `json:"components"`
	KeyID      string `json:"keyId"`
	Algorithm  string `json:"algorithm,omitempty"`
	Created    *int64 `json:"created,omitempty"`
	Expires    *int64 `json:"expires,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Tag        string `json:"tag,omitempty"`
}

func loadVectors(t *testing.T) []vectorFile {
	t.Helper()
	pattern := filepath.Join("..", "testdata", "vectors", "*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob vectors: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no vector files found")
	}

	var vectors []vectorFile
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var v vectorFile
		if err := json.Unmarshal(data, &v); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		vectors = append(vectors, v)
	}
	return vectors
}

func buildMessage(t *testing.T, vm vectorMessage) Message {
	t.Helper()
	headers := make(http.Header)
	for _, h := range vm.Headers {
		headers.Add(h[0], h[1])
	}

	if vm.Type == "request" {
		u, err := url.Parse(vm.URL)
		if err != nil {
			t.Fatalf("parse url %q: %v", vm.URL, err)
		}
		return &RawMessage{
			IsReq:     true,
			Meth:      vm.Method,
			TargetURI: u,
			Headers:   headers,
		}
	}

	return &RawMessage{
		IsReq:   false,
		Status:  vm.StatusCode,
		Headers: headers,
	}
}

func parseComponents(t *testing.T, raw []any) []ComponentIdentifier {
	t.Helper()
	var components []ComponentIdentifier
	for _, item := range raw {
		switch v := item.(type) {
		case string:
			components = append(components, Component(v))
		case map[string]any:
			name := v["name"].(string)
			params := NewSFVParams()
			if p, ok := v["params"].(map[string]any); ok {
				for k, val := range p {
					params.Set(k, val.(string))
				}
			}
			components = append(components, ComponentWithParams(name, params))
		default:
			t.Fatalf("unexpected component type: %T", item)
		}
	}
	return components
}

func buildSigParams(t *testing.T, vsp vectorSigParams) SignatureParameters {
	t.Helper()
	components := parseComponents(t, vsp.Components)
	sp := SignatureParameters{
		Components: components,
		KeyID:      vsp.KeyID,
		Created:    vsp.Created,
		Expires:    vsp.Expires,
	}
	// Note: we do NOT set sp.Algorithm here. The RFC test vectors don't include
	// "alg" in the serialized signature parameters. The algorithm is determined
	// by the key, not the signature params.
	if vsp.Nonce != "" {
		sp.Nonce = &vsp.Nonce
	}
	if vsp.Tag != "" {
		sp.Tag = &vsp.Tag
	}
	return sp
}

func loadSigningKey(t *testing.T, v vectorFile) SigningKey {
	t.Helper()
	keyPath := filepath.Join("..", "testdata", v.KeyFile)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key %s: %v", keyPath, err)
	}

	alg := Algorithm(v.SigningParams.Algorithm)
	keyID := v.SigningParams.KeyID

	switch alg {
	case AlgorithmHMACSHA256:
		// Key file is base64-encoded shared secret
		secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatalf("decode HMAC secret: %v", err)
		}
		return NewHMACSHA256Key(keyID, secret)

	case AlgorithmEd25519:
		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatal("failed to decode Ed25519 PEM")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse Ed25519 key: %v", err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("expected ed25519.PrivateKey, got %T", key)
		}
		return NewEd25519SigningKey(keyID, edKey)

	case AlgorithmRSAPSSSHA512:
		rsaKey, err := ParseRSAPSSPrivateKeyPEM(data)
		if err != nil {
			t.Fatalf("parse RSA-PSS key: %v", err)
		}
		return NewRSAPSSSigningKey(keyID, rsaKey)

	case AlgorithmECDSAP256SHA256:
		block, _ := pem.Decode(data)
		if block == nil {
			t.Fatal("failed to decode EC PEM")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			t.Fatalf("parse EC key: %v", err)
		}
		return NewECDSAP256SigningKey(keyID, key)

	default:
		t.Fatalf("unknown algorithm: %s", alg)
		return nil
	}
}

func loadVerifyingKey(t *testing.T, v vectorFile) VerifyingKey {
	t.Helper()
	alg := Algorithm(v.SigningParams.Algorithm)
	keyID := v.SigningParams.KeyID

	if alg == AlgorithmHMACSHA256 {
		// HMAC key is both signing and verifying
		keyPath := filepath.Join("..", "testdata", v.KeyFile)
		data, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatalf("read key %s: %v", keyPath, err)
		}
		secret, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatalf("decode HMAC secret: %v", err)
		}
		return NewHMACSHA256Key(keyID, secret)
	}

	if v.PubKeyFile == "" {
		t.Skip("no public key file specified")
	}

	keyPath := filepath.Join("..", "testdata", v.PubKeyFile)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read pubkey %s: %v", keyPath, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("failed to decode public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}

	switch alg {
	case AlgorithmRSAPSSSHA512:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("expected *rsa.PublicKey, got %T", pub)
		}
		return NewRSAPSSVerifyingKey(keyID, rsaPub)
	case AlgorithmECDSAP256SHA256:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
		}
		return NewECDSAP256VerifyingKey(keyID, ecPub)
	case AlgorithmEd25519:
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("expected ed25519.PublicKey, got %T", pub)
		}
		return NewEd25519VerifyingKey(keyID, edPub)
	default:
		t.Fatalf("unknown algorithm: %s", alg)
		return nil
	}
}

// TestVectorSignatureBase verifies that we produce the exact signature base
// string from the RFC test vectors.
func TestVectorSignatureBase(t *testing.T) {
	vectors := loadVectors(t)
	for _, v := range vectors {
		t.Run(v.ID+"-"+v.Description, func(t *testing.T) {
			msg := buildMessage(t, v.Message)
			params := buildSigParams(t, v.SigningParams)

			var reqMsg Message
			if v.RequestMessage != nil {
				reqMsg = buildMessage(t, *v.RequestMessage)
			}

			base, sigInput, err := BuildSignatureBase(msg, params, reqMsg)
			if err != nil {
				t.Fatalf("BuildSignatureBase: %v", err)
			}

			if string(base) != v.ExpectedBase {
				t.Errorf("signature base mismatch\ngot:\n%s\n\nwant:\n%s", string(base), v.ExpectedBase)
			}

			// Check that the signature input value (without label prefix) matches
			expectedInput := v.ExpectedSignatureInput
			// Strip the label= prefix from expected
			labelPrefix := v.SigningParams.Label + "="
			if strings.HasPrefix(expectedInput, labelPrefix) {
				expectedInput = expectedInput[len(labelPrefix):]
			}
			if sigInput != expectedInput {
				t.Errorf("signature-input mismatch\ngot:  %s\nwant: %s", sigInput, expectedInput)
			}
		})
	}
}

// TestVectorDeterministicSignatures verifies that deterministic algorithms
// (Ed25519, HMAC-SHA256) produce the exact expected signature.
func TestVectorDeterministicSignatures(t *testing.T) {
	vectors := loadVectors(t)
	for _, v := range vectors {
		if !v.Deterministic || v.ExpectedSignature == "" {
			continue
		}
		t.Run(v.ID+"-"+v.Description, func(t *testing.T) {
			msg := buildMessage(t, v.Message)
			params := buildSigParams(t, v.SigningParams)
			key := loadSigningKey(t, v)

			var reqMsg Message
			if v.RequestMessage != nil {
				reqMsg = buildMessage(t, *v.RequestMessage)
			}

			result, err := SignMessage(msg, v.SigningParams.Label, params, key, reqMsg)
			if err != nil {
				t.Fatalf("SignMessage: %v", err)
			}

			gotSig := base64.StdEncoding.EncodeToString(result.Signature)
			if gotSig != v.ExpectedSignature {
				t.Errorf("signature mismatch\ngot:  %s\nwant: %s", gotSig, v.ExpectedSignature)
			}
		})
	}
}

// TestVectorVerifySignatures verifies that all RFC test vector signatures
// (both deterministic and non-deterministic) can be verified with the public key.
func TestVectorVerifySignatures(t *testing.T) {
	vectors := loadVectors(t)
	for _, v := range vectors {
		sigB64 := v.ExpectedSignature
		if sigB64 == "" {
			sigB64 = v.VerifyOnlySignature
		}
		if sigB64 == "" {
			continue
		}

		t.Run(v.ID+"-verify-"+v.Description, func(t *testing.T) {
			sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}

			verifyKey := loadVerifyingKey(t, v)

			// Build the signature base from the expected base string
			valid, err := verifyKey.Verify([]byte(v.ExpectedBase), sigBytes)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !valid {
				t.Error("signature verification failed")
			}
		})
	}
}

// TestVectorSignAndVerifyRoundTrip signs with the private key and verifies
// with the public key for all test vectors.
func TestVectorSignAndVerifyRoundTrip(t *testing.T) {
	vectors := loadVectors(t)
	for _, v := range vectors {
		t.Run(v.ID+"-roundtrip-"+v.Description, func(t *testing.T) {
			msg := buildMessage(t, v.Message)
			params := buildSigParams(t, v.SigningParams)
			sigKey := loadSigningKey(t, v)
			verifyKey := loadVerifyingKey(t, v)

			var reqMsg Message
			if v.RequestMessage != nil {
				reqMsg = buildMessage(t, *v.RequestMessage)
			}

			result, err := SignMessage(msg, v.SigningParams.Label, params, sigKey, reqMsg)
			if err != nil {
				t.Fatalf("SignMessage: %v", err)
			}

			valid, err := verifyKey.Verify([]byte(v.ExpectedBase), result.Signature)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if !valid {
				t.Error("round-trip signature verification failed")
			}
		})
	}
}
