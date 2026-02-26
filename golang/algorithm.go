package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

// Algorithm identifies a signature algorithm per RFC 9421 Section 3.3.
type Algorithm string

const (
	AlgorithmRSAPSSSHA512    Algorithm = "rsa-pss-sha512"
	AlgorithmECDSAP256SHA256 Algorithm = "ecdsa-p256-sha256"
	AlgorithmEd25519         Algorithm = "ed25519"
	AlgorithmHMACSHA256      Algorithm = "hmac-sha256"
)

// algorithmSigner dispatches signing to the right algorithm.
func algorithmSign(alg Algorithm, key crypto.Signer, data []byte) ([]byte, error) {
	switch alg {
	case AlgorithmRSAPSSSHA512:
		return signRSAPSS(key, data)
	case AlgorithmECDSAP256SHA256:
		return signECDSAP256(key, data)
	case AlgorithmEd25519:
		return signEd25519(key, data)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownAlgorithm, alg)
	}
}

func algorithmVerify(alg Algorithm, pub crypto.PublicKey, data, sig []byte) (bool, error) {
	switch alg {
	case AlgorithmRSAPSSSHA512:
		return verifyRSAPSS(pub, data, sig)
	case AlgorithmECDSAP256SHA256:
		return verifyECDSAP256(pub, data, sig)
	case AlgorithmEd25519:
		return verifyEd25519(pub, data, sig)
	default:
		return false, fmt.Errorf("%w: %s", ErrUnknownAlgorithm, alg)
	}
}

// --- RSA-PSS-SHA512 ---

func signRSAPSS(key crypto.Signer, data []byte) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected *rsa.PrivateKey", ErrInvalidKey)
	}
	h := sha512.Sum512(data)
	return rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA512, h[:], &rsa.PSSOptions{
		SaltLength: 64,
		Hash:       crypto.SHA512,
	})
}

func verifyRSAPSS(pub crypto.PublicKey, data, sig []byte) (bool, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("%w: expected *rsa.PublicKey", ErrInvalidKey)
	}
	h := sha512.Sum512(data)
	err := rsa.VerifyPSS(rsaPub, crypto.SHA512, h[:], sig, &rsa.PSSOptions{
		SaltLength: 64,
		Hash:       crypto.SHA512,
	})
	if err != nil {
		return false, nil
	}
	return true, nil
}

// --- ECDSA-P256-SHA256 ---

func signECDSAP256(key crypto.Signer, data []byte) ([]byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected *ecdsa.PrivateKey", ErrInvalidKey)
	}
	if ecKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: expected P-256 curve", ErrInvalidKey)
	}
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, h[:])
	if err != nil {
		return nil, err
	}
	// RFC 9421 Section 3.3.3: signature is r || s, each 32 bytes, big-endian
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

func verifyECDSAP256(pub crypto.PublicKey, data, sig []byte) (bool, error) {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("%w: expected *ecdsa.PublicKey", ErrInvalidKey)
	}
	if ecPub.Curve != elliptic.P256() {
		return false, fmt.Errorf("%w: expected P-256 curve", ErrInvalidKey)
	}
	if len(sig) != 64 {
		return false, nil
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	h := sha256.Sum256(data)
	return ecdsa.Verify(ecPub, h[:], r, s), nil
}

// --- Ed25519 ---

func signEd25519(key crypto.Signer, data []byte) ([]byte, error) {
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected ed25519.PrivateKey", ErrInvalidKey)
	}
	return ed25519.Sign(edKey, data), nil
}

func verifyEd25519(pub crypto.PublicKey, data, sig []byte) (bool, error) {
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("%w: expected ed25519.PublicKey", ErrInvalidKey)
	}
	return ed25519.Verify(edPub, data, sig), nil
}

// --- HMAC-SHA256 ---

func signHMACSHA256(secret []byte, data []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("httpsig: empty HMAC secret")
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}

func verifyHMACSHA256(secret []byte, data, sig []byte) (bool, error) {
	expected, err := signHMACSHA256(secret, data)
	if err != nil {
		return false, err
	}
	return hmac.Equal(sig, expected), nil
}
