package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

// SigningKey can produce signatures for a given algorithm.
type SigningKey interface {
	KeyID() string
	Algorithm() Algorithm
	Sign(data []byte) ([]byte, error)
}

// VerifyingKey can verify signatures for a given algorithm.
type VerifyingKey interface {
	KeyID() string
	Algorithm() Algorithm
	Verify(data, signature []byte) (bool, error)
}

// KeyProvider resolves a key ID to a VerifyingKey for signature verification.
type KeyProvider func(keyID string, algorithm Algorithm) (VerifyingKey, error)

// --- Asymmetric key pairs (RSA-PSS, ECDSA, Ed25519) ---

type asymmetricSigningKey struct {
	keyID string
	alg   Algorithm
	key   crypto.Signer
}

func (k *asymmetricSigningKey) KeyID() string      { return k.keyID }
func (k *asymmetricSigningKey) Algorithm() Algorithm { return k.alg }
func (k *asymmetricSigningKey) Sign(data []byte) ([]byte, error) {
	return algorithmSign(k.alg, k.key, data)
}

type asymmetricVerifyingKey struct {
	keyID string
	alg   Algorithm
	pub   crypto.PublicKey
}

func (k *asymmetricVerifyingKey) KeyID() string      { return k.keyID }
func (k *asymmetricVerifyingKey) Algorithm() Algorithm { return k.alg }
func (k *asymmetricVerifyingKey) Verify(data, signature []byte) (bool, error) {
	return algorithmVerify(k.alg, k.pub, data, signature)
}

// NewRSAPSSSigningKey creates a SigningKey for rsa-pss-sha512.
func NewRSAPSSSigningKey(keyID string, key *rsa.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmRSAPSSSHA512, key: key}
}

// NewRSAPSSVerifyingKey creates a VerifyingKey for rsa-pss-sha512.
func NewRSAPSSVerifyingKey(keyID string, pub *rsa.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmRSAPSSSHA512, pub: pub}
}

// NewECDSAP256SigningKey creates a SigningKey for ecdsa-p256-sha256.
func NewECDSAP256SigningKey(keyID string, key *ecdsa.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmECDSAP256SHA256, key: key}
}

// NewECDSAP256VerifyingKey creates a VerifyingKey for ecdsa-p256-sha256.
func NewECDSAP256VerifyingKey(keyID string, pub *ecdsa.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmECDSAP256SHA256, pub: pub}
}

// NewEd25519SigningKey creates a SigningKey for ed25519.
func NewEd25519SigningKey(keyID string, key ed25519.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmEd25519, key: key}
}

// NewEd25519VerifyingKey creates a VerifyingKey for ed25519.
func NewEd25519VerifyingKey(keyID string, pub ed25519.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmEd25519, pub: pub}
}

// --- HMAC (symmetric) ---

type hmacKey struct {
	keyID  string
	secret []byte
}

func (k *hmacKey) KeyID() string      { return k.keyID }
func (k *hmacKey) Algorithm() Algorithm { return k.AlgorithmHMAC() }
func (k *hmacKey) AlgorithmHMAC() Algorithm { return AlgorithmHMACSHA256 }
func (k *hmacKey) Sign(data []byte) ([]byte, error) {
	return signHMACSHA256(k.secret, data)
}
func (k *hmacKey) Verify(data, signature []byte) (bool, error) {
	return verifyHMACSHA256(k.secret, data, signature)
}

// NewHMACSHA256Key creates a key that implements both SigningKey and VerifyingKey
// for hmac-sha256.
func NewHMACSHA256Key(keyID string, secret []byte) *hmacKey {
	s := make([]byte, len(secret))
	copy(s, secret)
	return &hmacKey{keyID: keyID, secret: s}
}

// --- crypto.Signer adapter (for HSM, PKCS#11, etc.) ---

// NewSignerKey creates a SigningKey from any crypto.Signer, useful for
// HSM/PKCS#11 backends that implement the crypto.Signer interface.
func NewSignerKey(keyID string, alg Algorithm, signer crypto.Signer) (SigningKey, error) {
	switch alg {
	case AlgorithmRSAPSSSHA512, AlgorithmECDSAP256SHA256, AlgorithmEd25519:
		return &asymmetricSigningKey{keyID: keyID, alg: alg, key: signer}, nil
	default:
		return nil, fmt.Errorf("%w: %s not supported with crypto.Signer", ErrUnknownAlgorithm, alg)
	}
}
