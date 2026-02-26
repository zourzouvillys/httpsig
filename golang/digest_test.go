package httpsig

import "testing"

func TestContentDigest(t *testing.T) {
	body := []byte(`{"hello": "world"}`)

	t.Run("sha-256", func(t *testing.T) {
		got, err := ContentDigest(body, DigestSHA256)
		if err != nil {
			t.Fatalf("ContentDigest: %v", err)
		}
		if got[:8] != "sha-256=" {
			t.Errorf("expected sha-256= prefix, got %q", got[:8])
		}
	})

	t.Run("sha-512", func(t *testing.T) {
		got, err := ContentDigest(body, DigestSHA512)
		if err != nil {
			t.Fatalf("ContentDigest: %v", err)
		}
		want := "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
		if got != want {
			t.Errorf("got:  %s\nwant: %s", got, want)
		}
	})
}

func TestVerifyContentDigest(t *testing.T) {
	body := []byte(`{"hello": "world"}`)
	header := "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"

	ok, err := VerifyContentDigest(body, header)
	if err != nil {
		t.Fatalf("VerifyContentDigest: %v", err)
	}
	if !ok {
		t.Error("expected digest to verify")
	}
}

func TestVerifyContentDigestMismatch(t *testing.T) {
	body := []byte(`{"hello": "changed"}`)
	header := "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"

	ok, err := VerifyContentDigest(body, header)
	if err != nil {
		t.Fatalf("VerifyContentDigest: %v", err)
	}
	if ok {
		t.Error("expected digest to NOT verify with wrong body")
	}
}
