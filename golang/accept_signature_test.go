package httpsig

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"reflect"
	"testing"
)

func TestBuildParseRoundTrip(t *testing.T) {
	entries := map[string]SignatureRequirements{
		"sig1": {
			Components: []ComponentIdentifier{
				Component("@method"),
				Component("@authority"),
				Component("content-digest"),
			},
			KeyID:          "server-key-1",
			Algorithm:      AlgorithmECDSAP256SHA256,
			Tag:            "myapp",
			RequireCreated: true,
			RequireExpires: true,
		},
	}

	header := BuildAcceptSignature(entries)
	if header == "" {
		t.Fatal("BuildAcceptSignature returned empty string")
	}

	parsed, err := ParseAcceptSignature(header)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}

	if len(parsed) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(parsed))
	}

	got, ok := parsed["sig1"]
	if !ok {
		t.Fatal("missing sig1 entry")
	}

	want := entries["sig1"]
	if len(got.Components) != len(want.Components) {
		t.Fatalf("components: got %d, want %d", len(got.Components), len(want.Components))
	}
	for i := range want.Components {
		if serializeComponentID(got.Components[i]) != serializeComponentID(want.Components[i]) {
			t.Errorf("component[%d]: got %q, want %q",
				i, serializeComponentID(got.Components[i]), serializeComponentID(want.Components[i]))
		}
	}
	if got.KeyID != want.KeyID {
		t.Errorf("KeyID: got %q, want %q", got.KeyID, want.KeyID)
	}
	if got.Algorithm != want.Algorithm {
		t.Errorf("Algorithm: got %q, want %q", got.Algorithm, want.Algorithm)
	}
	if got.Tag != want.Tag {
		t.Errorf("Tag: got %q, want %q", got.Tag, want.Tag)
	}
	if got.RequireCreated != want.RequireCreated {
		t.Errorf("RequireCreated: got %v, want %v", got.RequireCreated, want.RequireCreated)
	}
	if got.RequireExpires != want.RequireExpires {
		t.Errorf("RequireExpires: got %v, want %v", got.RequireExpires, want.RequireExpires)
	}
}

func TestParseRFCStyleExample(t *testing.T) {
	input := `sig1=("@method" "@authority" "content-digest");keyid="server-key-1";alg="ecdsa-p256-sha256";created;expires;tag="myapp"`

	parsed, err := ParseAcceptSignature(input)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}

	got, ok := parsed["sig1"]
	if !ok {
		t.Fatal("missing sig1 entry")
	}

	if len(got.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(got.Components))
	}
	wantNames := []string{"@method", "@authority", "content-digest"}
	for i, name := range wantNames {
		if got.Components[i].Name != name {
			t.Errorf("component[%d]: got %q, want %q", i, got.Components[i].Name, name)
		}
	}

	if got.KeyID != "server-key-1" {
		t.Errorf("KeyID: got %q, want %q", got.KeyID, "server-key-1")
	}
	if got.Algorithm != AlgorithmECDSAP256SHA256 {
		t.Errorf("Algorithm: got %q, want %q", got.Algorithm, AlgorithmECDSAP256SHA256)
	}
	if got.Tag != "myapp" {
		t.Errorf("Tag: got %q, want %q", got.Tag, "myapp")
	}
	if !got.RequireCreated {
		t.Error("RequireCreated should be true")
	}
	if !got.RequireExpires {
		t.Error("RequireExpires should be true")
	}
}

func TestParseMultipleEntries(t *testing.T) {
	input := `sig1=("@method" "@authority");keyid="key-1", sig2=("@method" "content-type");keyid="key-2";alg="ed25519"`

	parsed, err := ParseAcceptSignature(input)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}

	if len(parsed) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parsed))
	}

	sig1, ok := parsed["sig1"]
	if !ok {
		t.Fatal("missing sig1")
	}
	if sig1.KeyID != "key-1" {
		t.Errorf("sig1.KeyID: got %q, want %q", sig1.KeyID, "key-1")
	}
	if len(sig1.Components) != 2 {
		t.Errorf("sig1 components: got %d, want 2", len(sig1.Components))
	}

	sig2, ok := parsed["sig2"]
	if !ok {
		t.Fatal("missing sig2")
	}
	if sig2.KeyID != "key-2" {
		t.Errorf("sig2.KeyID: got %q, want %q", sig2.KeyID, "key-2")
	}
	if sig2.Algorithm != AlgorithmEd25519 {
		t.Errorf("sig2.Algorithm: got %q, want %q", sig2.Algorithm, AlgorithmEd25519)
	}
	if len(sig2.Components) != 2 {
		t.Errorf("sig2 components: got %d, want 2", len(sig2.Components))
	}
}

func TestBuildParseMultipleEntries(t *testing.T) {
	entries := map[string]SignatureRequirements{
		"sig1": {
			Components: []ComponentIdentifier{Component("@method")},
			KeyID:      "key-a",
		},
		"sig2": {
			Components: []ComponentIdentifier{Component("@authority")},
			Algorithm:  AlgorithmEd25519,
		},
	}

	header := BuildAcceptSignature(entries)
	parsed, err := ParseAcceptSignature(header)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}

	if len(parsed) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(parsed))
	}
	if parsed["sig1"].KeyID != "key-a" {
		t.Errorf("sig1.KeyID: got %q, want %q", parsed["sig1"].KeyID, "key-a")
	}
	if parsed["sig2"].Algorithm != AlgorithmEd25519 {
		t.Errorf("sig2.Algorithm: got %q, want %q", parsed["sig2"].Algorithm, AlgorithmEd25519)
	}
}

func TestComponentWithParams(t *testing.T) {
	entries := map[string]SignatureRequirements{
		"sig1": {
			Components: []ComponentIdentifier{
				Component("@method"),
				QueryParam("foo"),
			},
		},
	}

	header := BuildAcceptSignature(entries)
	parsed, err := ParseAcceptSignature(header)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}

	got := parsed["sig1"]
	if len(got.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(got.Components))
	}

	// Verify the @query-param;name="foo" round-trips correctly.
	wantSerialized := `"@query-param";name="foo"`
	gotSerialized := serializeComponentID(got.Components[1])
	if gotSerialized != wantSerialized {
		t.Errorf("component[1]: got %q, want %q", gotSerialized, wantSerialized)
	}
}

func TestEmptyComponents(t *testing.T) {
	entries := map[string]SignatureRequirements{
		"sig1": {
			Components: []ComponentIdentifier{},
			KeyID:      "test-key",
		},
	}

	header := BuildAcceptSignature(entries)
	parsed, err := ParseAcceptSignature(header)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}

	got := parsed["sig1"]
	if len(got.Components) != 0 {
		t.Errorf("expected 0 components, got %d", len(got.Components))
	}
	if got.KeyID != "test-key" {
		t.Errorf("KeyID: got %q, want %q", got.KeyID, "test-key")
	}
}

func TestToSignatureParameters(t *testing.T) {
	req := SignatureRequirements{
		Components: []ComponentIdentifier{
			Component("@method"),
			Component("@authority"),
		},
		KeyID:     "my-key",
		Algorithm: AlgorithmECDSAP256SHA256,
		Tag:       "myapp",
	}

	created := int64(1618884473)
	expires := int64(1618884773)
	nonce := "abc123"

	params := req.ToSignatureParameters(&created, &expires, &nonce)

	if len(params.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(params.Components))
	}
	if params.KeyID != "my-key" {
		t.Errorf("KeyID: got %q, want %q", params.KeyID, "my-key")
	}
	if params.Algorithm != AlgorithmECDSAP256SHA256 {
		t.Errorf("Algorithm: got %q, want %q", params.Algorithm, AlgorithmECDSAP256SHA256)
	}
	if params.Tag == nil || *params.Tag != "myapp" {
		t.Errorf("Tag: got %v, want %q", params.Tag, "myapp")
	}
	if params.Created == nil || *params.Created != created {
		t.Errorf("Created: got %v, want %d", params.Created, created)
	}
	if params.Expires == nil || *params.Expires != expires {
		t.Errorf("Expires: got %v, want %d", params.Expires, expires)
	}
	if params.Nonce == nil || *params.Nonce != nonce {
		t.Errorf("Nonce: got %v, want %q", params.Nonce, nonce)
	}

	// Verify that the components are a copy, not a shared slice.
	req.Components[0] = Component("@path")
	if params.Components[0].Name != "@method" {
		t.Error("ToSignatureParameters should copy components, not share the slice")
	}
}

func TestToSignatureParametersNoTag(t *testing.T) {
	req := SignatureRequirements{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "k1",
	}
	params := req.ToSignatureParameters(Int64Ptr(100), nil, nil)
	if params.Tag != nil {
		t.Errorf("Tag should be nil when requirements Tag is empty, got %v", params.Tag)
	}
}

func TestVerifierWithRequirementsFiltersByKeyID(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := NewEd25519SigningKey("correct-key", priv)
	verifyingKey := NewEd25519VerifyingKey("correct-key", pub)

	// Sign a message.
	httpReq, _ := http.NewRequest("POST", "https://example.com/path", nil)
	httpReq.Header.Set("Content-Type", "application/json")
	msg := &RequestMessage{Req: httpReq}

	created := int64(1618884473)
	result, err := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{
			Component("@method"),
			Component("@authority"),
		},
		KeyID:   "correct-key",
		Created: &created,
	}, signingKey, nil)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	// Apply signature to request.
	httpReq.Header.Set("Signature-Input", SignatureInputHeader(result))
	httpReq.Header.Set("Signature", SignatureHeader(result))

	provider := func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "correct-key" {
			return verifyingKey, nil
		}
		return nil, ErrKeyNotFound
	}

	// Verify with matching keyID requirement -- should succeed.
	verifyResult, err := VerifyMessage(msg, provider, &VerifyOptions{
		Requirements: &SignatureRequirements{
			Components: []ComponentIdentifier{Component("@method")},
			KeyID:      "correct-key",
		},
	}, nil)
	if err != nil {
		t.Fatalf("VerifyMessage with matching keyID: %v", err)
	}
	if verifyResult.KeyID != "correct-key" {
		t.Errorf("KeyID: got %q, want %q", verifyResult.KeyID, "correct-key")
	}

	// Verify with wrong keyID requirement -- should fail.
	_, err = VerifyMessage(msg, provider, &VerifyOptions{
		Requirements: &SignatureRequirements{
			Components: []ComponentIdentifier{Component("@method")},
			KeyID:      "wrong-key",
		},
	}, nil)
	if err == nil {
		t.Fatal("expected verification to fail with wrong keyID requirement")
	}
}

func TestVerifierWithRequirementsFiltersByAlgorithm(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := NewEd25519SigningKey("test-key", priv)
	verifyingKey := NewEd25519VerifyingKey("test-key", pub)

	httpReq, _ := http.NewRequest("GET", "https://example.com/", nil)
	msg := &RequestMessage{Req: httpReq}

	result, err := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "test-key",
		Algorithm:  AlgorithmEd25519,
		Created:    Int64Ptr(1618884473),
	}, signingKey, nil)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	httpReq.Header.Set("Signature-Input", SignatureInputHeader(result))
	httpReq.Header.Set("Signature", SignatureHeader(result))

	provider := func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "test-key" {
			return verifyingKey, nil
		}
		return nil, ErrKeyNotFound
	}

	// Matching algorithm -- should succeed.
	_, err = VerifyMessage(msg, provider, &VerifyOptions{
		Requirements: &SignatureRequirements{
			Components: []ComponentIdentifier{Component("@method")},
			Algorithm:  AlgorithmEd25519,
		},
	}, nil)
	if err != nil {
		t.Fatalf("VerifyMessage with matching algorithm: %v", err)
	}

	// Wrong algorithm -- should fail.
	_, err = VerifyMessage(msg, provider, &VerifyOptions{
		Requirements: &SignatureRequirements{
			Components: []ComponentIdentifier{Component("@method")},
			Algorithm:  AlgorithmECDSAP256SHA256,
		},
	}, nil)
	if err == nil {
		t.Fatal("expected verification to fail with wrong algorithm requirement")
	}
}

func TestVerifierWithRequirementsFiltersByTag(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := NewEd25519SigningKey("test-key", priv)
	verifyingKey := NewEd25519VerifyingKey("test-key", pub)

	httpReq, _ := http.NewRequest("GET", "https://example.com/", nil)
	msg := &RequestMessage{Req: httpReq}

	tag := "myapp"
	result, err := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "test-key",
		Created:    Int64Ptr(1618884473),
		Tag:        &tag,
	}, signingKey, nil)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	httpReq.Header.Set("Signature-Input", SignatureInputHeader(result))
	httpReq.Header.Set("Signature", SignatureHeader(result))

	provider := func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "test-key" {
			return verifyingKey, nil
		}
		return nil, ErrKeyNotFound
	}

	// Matching tag -- should succeed.
	_, err = VerifyMessage(msg, provider, &VerifyOptions{
		Requirements: &SignatureRequirements{
			Components: []ComponentIdentifier{Component("@method")},
			Tag:        "myapp",
		},
	}, nil)
	if err != nil {
		t.Fatalf("VerifyMessage with matching tag: %v", err)
	}

	// Wrong tag -- should fail.
	_, err = VerifyMessage(msg, provider, &VerifyOptions{
		Requirements: &SignatureRequirements{
			Components: []ComponentIdentifier{Component("@method")},
			Tag:        "otherapp",
		},
	}, nil)
	if err == nil {
		t.Fatal("expected verification to fail with wrong tag requirement")
	}
}

func TestVerifierRequiredComponentsBackwardCompat(t *testing.T) {
	// Verify that RequiredComponents still works when Requirements is nil.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := NewEd25519SigningKey("test-key", priv)
	verifyingKey := NewEd25519VerifyingKey("test-key", pub)

	httpReq, _ := http.NewRequest("GET", "https://example.com/", nil)
	msg := &RequestMessage{Req: httpReq}

	result, err := SignMessage(msg, "sig1", SignatureParameters{
		Components: []ComponentIdentifier{Component("@method")},
		KeyID:      "test-key",
		Created:    Int64Ptr(1618884473),
	}, signingKey, nil)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	httpReq.Header.Set("Signature-Input", SignatureInputHeader(result))
	httpReq.Header.Set("Signature", SignatureHeader(result))

	provider := func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "test-key" {
			return verifyingKey, nil
		}
		return nil, ErrKeyNotFound
	}

	// RequiredComponents with a component that IS covered -- should succeed.
	_, err = VerifyMessage(msg, provider, &VerifyOptions{
		RequiredComponents: []ComponentIdentifier{Component("@method")},
	}, nil)
	if err != nil {
		t.Fatalf("VerifyMessage with matching RequiredComponents: %v", err)
	}

	// RequiredComponents with a component that is NOT covered -- should fail.
	_, err = VerifyMessage(msg, provider, &VerifyOptions{
		RequiredComponents: []ComponentIdentifier{Component("@authority")},
	}, nil)
	if err == nil {
		t.Fatal("expected verification to fail with missing RequiredComponents")
	}
}

func TestParseAcceptSignatureError(t *testing.T) {
	// Malformed input.
	_, err := ParseAcceptSignature("!!!invalid")
	if err == nil {
		t.Fatal("expected error for malformed input")
	}
}

func TestBuildAcceptSignatureEmpty(t *testing.T) {
	header := BuildAcceptSignature(map[string]SignatureRequirements{})
	if header != "" {
		t.Errorf("expected empty string for empty entries, got %q", header)
	}
}

func TestToSignatureParametersUsableWithSigner(t *testing.T) {
	// Verify that ToSignatureParameters produces params that work with SignMessage.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := NewEd25519SigningKey("my-key", priv)
	verifyingKey := NewEd25519VerifyingKey("my-key", pub)

	req := SignatureRequirements{
		Components: []ComponentIdentifier{
			Component("@method"),
			Component("@authority"),
		},
		KeyID: "my-key",
		Tag:   "test",
	}

	params := req.ToSignatureParameters(Int64Ptr(1618884473), nil, nil)

	httpReq, _ := http.NewRequest("GET", "https://example.com/", nil)
	msg := &RequestMessage{Req: httpReq}

	result, err := SignMessage(msg, "sig1", params, signingKey, nil)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	if result.Label != "sig1" {
		t.Errorf("Label: got %q, want %q", result.Label, "sig1")
	}

	// Verify the signed message.
	httpReq.Header.Set("Signature-Input", SignatureInputHeader(result))
	httpReq.Header.Set("Signature", SignatureHeader(result))

	provider := func(keyID string, alg Algorithm) (VerifyingKey, error) {
		if keyID == "my-key" {
			return verifyingKey, nil
		}
		return nil, ErrKeyNotFound
	}

	verifyResult, err := VerifyMessage(msg, provider, nil, nil)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if verifyResult.KeyID != "my-key" {
		t.Errorf("verified KeyID: got %q, want %q", verifyResult.KeyID, "my-key")
	}
}

func TestNilComponentsRoundTrip(t *testing.T) {
	// Nil components should work the same as empty components.
	entries := map[string]SignatureRequirements{
		"sig1": {
			Components: nil,
			KeyID:      "k",
		},
	}

	header := BuildAcceptSignature(entries)
	parsed, err := ParseAcceptSignature(header)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}
	got := parsed["sig1"]
	if len(got.Components) != 0 {
		t.Errorf("expected 0 components, got %d", len(got.Components))
	}
}

func TestRequirementsComponentsEquality(t *testing.T) {
	// Verify that ComponentWithKey round-trips correctly through Accept-Signature.
	entries := map[string]SignatureRequirements{
		"sig1": {
			Components: []ComponentIdentifier{
				ComponentWithKey("signature", "sig1"),
			},
		},
	}

	header := BuildAcceptSignature(entries)
	parsed, err := ParseAcceptSignature(header)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}

	got := parsed["sig1"]
	if len(got.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(got.Components))
	}
	if got.Components[0].Name != "signature" {
		t.Errorf("Name: got %q, want %q", got.Components[0].Name, "signature")
	}
	keyVal := got.Components[0].paramString("key")
	if keyVal != "sig1" {
		t.Errorf("key param: got %q, want %q", keyVal, "sig1")
	}
}

func TestOnlyRequireFlagsAsBooleans(t *testing.T) {
	// Verify that created and expires are serialized as bare booleans (;created, ;expires)
	// not as values.
	entries := map[string]SignatureRequirements{
		"sig1": {
			Components:     []ComponentIdentifier{Component("@method")},
			RequireCreated: true,
			RequireExpires: true,
		},
	}

	header := BuildAcceptSignature(entries)
	parsed, err := ParseAcceptSignature(header)
	if err != nil {
		t.Fatalf("ParseAcceptSignature: %v", err)
	}

	got := parsed["sig1"]
	if !got.RequireCreated {
		t.Error("RequireCreated should be true")
	}
	if !got.RequireExpires {
		t.Error("RequireExpires should be true")
	}
}

func TestRequirementsFieldsReflect(t *testing.T) {
	// Verify the type has exactly the fields we expect.
	r := SignatureRequirements{}
	rt := reflect.TypeOf(r)
	expectedFields := map[string]bool{
		"Components":     true,
		"KeyID":          true,
		"Algorithm":      true,
		"Tag":            true,
		"RequireCreated": true,
		"RequireExpires": true,
	}
	if rt.NumField() != len(expectedFields) {
		t.Errorf("expected %d fields, got %d", len(expectedFields), rt.NumField())
	}
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		if !expectedFields[name] {
			t.Errorf("unexpected field %q", name)
		}
	}
}
