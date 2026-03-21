package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

// NewRSAPSSSHA384SigningKey creates a SigningKey for rsa-pss-sha384.
func NewRSAPSSSHA384SigningKey(keyID string, key *rsa.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmRSAPSSSHA384, key: key}
}

// NewRSAPSSSHA384VerifyingKey creates a VerifyingKey for rsa-pss-sha384.
func NewRSAPSSSHA384VerifyingKey(keyID string, pub *rsa.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmRSAPSSSHA384, pub: pub}
}

// NewRSAPSSSHA256SigningKey creates a SigningKey for rsa-pss-sha256.
func NewRSAPSSSHA256SigningKey(keyID string, key *rsa.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmRSAPSSSHA256, key: key}
}

// NewRSAPSSSHA256VerifyingKey creates a VerifyingKey for rsa-pss-sha256.
func NewRSAPSSSHA256VerifyingKey(keyID string, pub *rsa.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmRSAPSSSHA256, pub: pub}
}

// NewRSAV15SHA256SigningKey creates a SigningKey for rsa-v1_5-sha256.
func NewRSAV15SHA256SigningKey(keyID string, key *rsa.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmRSAV15SHA256, key: key}
}

// NewRSAV15SHA256VerifyingKey creates a VerifyingKey for rsa-v1_5-sha256.
func NewRSAV15SHA256VerifyingKey(keyID string, pub *rsa.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmRSAV15SHA256, pub: pub}
}

// NewECDSAP256SigningKey creates a SigningKey for ecdsa-p256-sha256.
func NewECDSAP256SigningKey(keyID string, key *ecdsa.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmECDSAP256SHA256, key: key}
}

// NewECDSAP256VerifyingKey creates a VerifyingKey for ecdsa-p256-sha256.
func NewECDSAP256VerifyingKey(keyID string, pub *ecdsa.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmECDSAP256SHA256, pub: pub}
}

// NewECDSAP384SigningKey creates a SigningKey for ecdsa-p384-sha384.
func NewECDSAP384SigningKey(keyID string, key *ecdsa.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmECDSAP384SHA384, key: key}
}

// NewECDSAP384VerifyingKey creates a VerifyingKey for ecdsa-p384-sha384.
func NewECDSAP384VerifyingKey(keyID string, pub *ecdsa.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmECDSAP384SHA384, pub: pub}
}

// NewECDSAP521SigningKey creates a SigningKey for ecdsa-p521-sha512.
func NewECDSAP521SigningKey(keyID string, key *ecdsa.PrivateKey) SigningKey {
	return &asymmetricSigningKey{keyID: keyID, alg: AlgorithmECDSAP521SHA512, key: key}
}

// NewECDSAP521VerifyingKey creates a VerifyingKey for ecdsa-p521-sha512.
func NewECDSAP521VerifyingKey(keyID string, pub *ecdsa.PublicKey) VerifyingKey {
	return &asymmetricVerifyingKey{keyID: keyID, alg: AlgorithmECDSAP521SHA512, pub: pub}
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
	alg    Algorithm
	secret []byte
	signFn func([]byte, []byte) ([]byte, error)
	verFn  func([]byte, []byte, []byte) (bool, error)
}

func (k *hmacKey) KeyID() string        { return k.keyID }
func (k *hmacKey) Algorithm() Algorithm  { return k.alg }
func (k *hmacKey) Sign(data []byte) ([]byte, error) {
	return k.signFn(k.secret, data)
}
func (k *hmacKey) Verify(data, signature []byte) (bool, error) {
	return k.verFn(k.secret, data, signature)
}

func newHMACKey(keyID string, alg Algorithm, secret []byte,
	signFn func([]byte, []byte) ([]byte, error),
	verFn func([]byte, []byte, []byte) (bool, error),
) *hmacKey {
	s := make([]byte, len(secret))
	copy(s, secret)
	return &hmacKey{keyID: keyID, alg: alg, secret: s, signFn: signFn, verFn: verFn}
}

// NewHMACSHA256Key creates a key that implements both SigningKey and VerifyingKey
// for hmac-sha256.
func NewHMACSHA256Key(keyID string, secret []byte) *hmacKey {
	return newHMACKey(keyID, AlgorithmHMACSHA256, secret, signHMACSHA256, verifyHMACSHA256)
}

// NewHMACSHA384Key creates a key that implements both SigningKey and VerifyingKey
// for hmac-sha384.
func NewHMACSHA384Key(keyID string, secret []byte) *hmacKey {
	return newHMACKey(keyID, AlgorithmHMACSHA384, secret, signHMACSHA384, verifyHMACSHA384)
}

// NewHMACSHA512Key creates a key that implements both SigningKey and VerifyingKey
// for hmac-sha512.
func NewHMACSHA512Key(keyID string, secret []byte) *hmacKey {
	return newHMACKey(keyID, AlgorithmHMACSHA512, secret, signHMACSHA512, verifyHMACSHA512)
}

// --- crypto.Signer adapter (for HSM, PKCS#11, etc.) ---

// NewSignerKey creates a SigningKey from any crypto.Signer, useful for
// HSM/PKCS#11 backends that implement the crypto.Signer interface.
func NewSignerKey(keyID string, alg Algorithm, signer crypto.Signer) (SigningKey, error) {
	switch alg {
	case AlgorithmRSAPSSSHA512, AlgorithmRSAPSSSHA384, AlgorithmRSAPSSSHA256,
		AlgorithmRSAV15SHA256,
		AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384, AlgorithmECDSAP521SHA512,
		AlgorithmEd25519:
		return &asymmetricSigningKey{keyID: keyID, alg: alg, key: signer}, nil
	default:
		return nil, fmt.Errorf("%w: %s not supported with crypto.Signer", ErrUnknownAlgorithm, alg)
	}
}

// --- KeyPair and auto-detection ---

// KeyPair bundles a SigningKey and VerifyingKey that share the same key ID and algorithm.
type KeyPair struct {
	Signing   SigningKey
	Verifying VerifyingKey
}

// KeyID returns the key ID shared by both halves.
func (kp *KeyPair) KeyID() string { return kp.Signing.KeyID() }

// Algorithm returns the algorithm shared by both halves.
func (kp *KeyPair) Algorithm() Algorithm { return kp.Signing.Algorithm() }

// detectAlgorithm infers the Algorithm from a public key's concrete type.
func detectAlgorithm(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return AlgorithmRSAPSSSHA512, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return AlgorithmECDSAP256SHA256, nil
		case elliptic.P384():
			return AlgorithmECDSAP384SHA384, nil
		case elliptic.P521():
			return AlgorithmECDSAP521SHA512, nil
		default:
			return "", fmt.Errorf("%w: unsupported EC curve", ErrInvalidKey)
		}
	case ed25519.PublicKey:
		return AlgorithmEd25519, nil
	default:
		return "", fmt.Errorf("%w: unsupported key type %T", ErrInvalidKey, pub)
	}
}

// NewKeyPair creates a KeyPair by auto-detecting the algorithm from the private key type
// and deriving the corresponding public key.
func NewKeyPair(keyID string, key crypto.PrivateKey) (*KeyPair, error) {
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%w: key does not implement crypto.Signer", ErrInvalidKey)
	}
	pub := signer.Public()
	alg, err := detectAlgorithm(pub)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Signing:   &asymmetricSigningKey{keyID: keyID, alg: alg, key: signer},
		Verifying: &asymmetricVerifyingKey{keyID: keyID, alg: alg, pub: pub},
	}, nil
}

// NewHMACKeyPair creates a KeyPair for HMAC-SHA256 where the same secret backs both sides.
func NewHMACKeyPair(keyID string, secret []byte) *KeyPair {
	k := NewHMACSHA256Key(keyID, secret)
	return &KeyPair{Signing: k, Verifying: k}
}

// NewSigningKeyFromSigner creates a SigningKey by auto-detecting the algorithm from the
// signer's public key type. This is the auto-detecting alternative to NewSignerKey.
func NewSigningKeyFromSigner(keyID string, signer crypto.Signer) (SigningKey, error) {
	alg, err := detectAlgorithm(signer.Public())
	if err != nil {
		return nil, err
	}
	return &asymmetricSigningKey{keyID: keyID, alg: alg, key: signer}, nil
}

// NewVerifyingKeyFromPublic creates a VerifyingKey by auto-detecting the algorithm from
// the public key type.
func NewVerifyingKeyFromPublic(keyID string, pub crypto.PublicKey) (VerifyingKey, error) {
	alg, err := detectAlgorithm(pub)
	if err != nil {
		return nil, err
	}
	return &asymmetricVerifyingKey{keyID: keyID, alg: alg, pub: pub}, nil
}
