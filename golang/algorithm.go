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
	"hash"
	"math/big"
)

// Algorithm identifies a signature algorithm per RFC 9421 Section 3.3.
type Algorithm string

const (
	AlgorithmRSAPSSSHA512    Algorithm = "rsa-pss-sha512"
	AlgorithmRSAPSSSHA384    Algorithm = "rsa-pss-sha384"
	AlgorithmRSAPSSSHA256    Algorithm = "rsa-pss-sha256"
	AlgorithmRSAV15SHA256    Algorithm = "rsa-v1_5-sha256"
	AlgorithmECDSAP256SHA256 Algorithm = "ecdsa-p256-sha256"
	AlgorithmECDSAP384SHA384 Algorithm = "ecdsa-p384-sha384"
	AlgorithmECDSAP521SHA512 Algorithm = "ecdsa-p521-sha512"
	AlgorithmEd25519         Algorithm = "ed25519"
	AlgorithmHMACSHA256      Algorithm = "hmac-sha256"
	AlgorithmHMACSHA384      Algorithm = "hmac-sha384"
	AlgorithmHMACSHA512      Algorithm = "hmac-sha512"
)

// algorithmSigner dispatches signing to the right algorithm.
func algorithmSign(alg Algorithm, key crypto.Signer, data []byte) ([]byte, error) {
	switch alg {
	case AlgorithmRSAPSSSHA512:
		return signRSAPSS(key, crypto.SHA512, 64, data)
	case AlgorithmRSAPSSSHA384:
		return signRSAPSS(key, crypto.SHA384, 48, data)
	case AlgorithmRSAPSSSHA256:
		return signRSAPSS(key, crypto.SHA256, 32, data)
	case AlgorithmRSAV15SHA256:
		return signRSAV15(key, crypto.SHA256, data)
	case AlgorithmECDSAP256SHA256:
		return signECDSA(key, elliptic.P256(), crypto.SHA256, 32, data)
	case AlgorithmECDSAP384SHA384:
		return signECDSA(key, elliptic.P384(), crypto.SHA384, 48, data)
	case AlgorithmECDSAP521SHA512:
		return signECDSA(key, elliptic.P521(), crypto.SHA512, 66, data)
	case AlgorithmEd25519:
		return signEd25519(key, data)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnknownAlgorithm, alg)
	}
}

func algorithmVerify(alg Algorithm, pub crypto.PublicKey, data, sig []byte) (bool, error) {
	switch alg {
	case AlgorithmRSAPSSSHA512:
		return verifyRSAPSS(pub, crypto.SHA512, 64, data, sig)
	case AlgorithmRSAPSSSHA384:
		return verifyRSAPSS(pub, crypto.SHA384, 48, data, sig)
	case AlgorithmRSAPSSSHA256:
		return verifyRSAPSS(pub, crypto.SHA256, 32, data, sig)
	case AlgorithmRSAV15SHA256:
		return verifyRSAV15(pub, crypto.SHA256, data, sig)
	case AlgorithmECDSAP256SHA256:
		return verifyECDSA(pub, elliptic.P256(), crypto.SHA256, 32, data, sig)
	case AlgorithmECDSAP384SHA384:
		return verifyECDSA(pub, elliptic.P384(), crypto.SHA384, 48, data, sig)
	case AlgorithmECDSAP521SHA512:
		return verifyECDSA(pub, elliptic.P521(), crypto.SHA512, 66, data, sig)
	case AlgorithmEd25519:
		return verifyEd25519(pub, data, sig)
	default:
		return false, fmt.Errorf("%w: %s", ErrUnknownAlgorithm, alg)
	}
}

// --- RSA-PSS ---

func signRSAPSS(key crypto.Signer, hash crypto.Hash, saltLen int, data []byte) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected *rsa.PrivateKey", ErrInvalidKey)
	}
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.SignPSS(rand.Reader, rsaKey, hash, digest, &rsa.PSSOptions{
		SaltLength: saltLen,
		Hash:       hash,
	})
}

func verifyRSAPSS(pub crypto.PublicKey, hash crypto.Hash, saltLen int, data, sig []byte) (bool, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("%w: expected *rsa.PublicKey", ErrInvalidKey)
	}
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)
	err := rsa.VerifyPSS(rsaPub, hash, digest, sig, &rsa.PSSOptions{
		SaltLength: saltLen,
		Hash:       hash,
	})
	if err != nil {
		return false, nil
	}
	return true, nil
}

// --- RSA PKCS1v1.5 ---

func signRSAV15(key crypto.Signer, hash crypto.Hash, data []byte) ([]byte, error) {
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected *rsa.PrivateKey", ErrInvalidKey)
	}
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest)
}

func verifyRSAV15(pub crypto.PublicKey, hash crypto.Hash, data, sig []byte) (bool, error) {
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("%w: expected *rsa.PublicKey", ErrInvalidKey)
	}
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)
	err := rsa.VerifyPKCS1v15(rsaPub, hash, digest, sig)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// --- ECDSA ---

func signECDSA(key crypto.Signer, curve elliptic.Curve, hash crypto.Hash, fieldLen int, data []byte) ([]byte, error) {
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected *ecdsa.PrivateKey", ErrInvalidKey)
	}
	if ecKey.Curve != curve {
		return nil, fmt.Errorf("%w: expected %s curve", ErrInvalidKey, curve.Params().Name)
	}
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, ecKey, digest)
	if err != nil {
		return nil, err
	}
	// RFC 9421: signature is r || s, each fieldLen bytes, big-endian, zero-padded
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigLen := fieldLen * 2
	sig := make([]byte, sigLen)
	copy(sig[fieldLen-len(rBytes):fieldLen], rBytes)
	copy(sig[sigLen-len(sBytes):sigLen], sBytes)
	return sig, nil
}

func verifyECDSA(pub crypto.PublicKey, curve elliptic.Curve, hash crypto.Hash, fieldLen int, data, sig []byte) (bool, error) {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("%w: expected *ecdsa.PublicKey", ErrInvalidKey)
	}
	if ecPub.Curve != curve {
		return false, fmt.Errorf("%w: expected %s curve", ErrInvalidKey, curve.Params().Name)
	}
	sigLen := fieldLen * 2
	if len(sig) != sigLen {
		return false, nil
	}
	r := new(big.Int).SetBytes(sig[:fieldLen])
	s := new(big.Int).SetBytes(sig[fieldLen:])
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)
	return ecdsa.Verify(ecPub, digest, r, s), nil
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

// --- HMAC ---

func signHMACSHA256(secret []byte, data []byte) ([]byte, error) {
	return signHMAC(secret, sha256.New, data)
}

func verifyHMACSHA256(secret []byte, data, sig []byte) (bool, error) {
	return verifyHMAC(secret, sha256.New, data, sig)
}

func signHMACSHA384(secret []byte, data []byte) ([]byte, error) {
	return signHMAC(secret, sha512.New384, data)
}

func verifyHMACSHA384(secret []byte, data, sig []byte) (bool, error) {
	return verifyHMAC(secret, sha512.New384, data, sig)
}

func signHMACSHA512(secret []byte, data []byte) ([]byte, error) {
	return signHMAC(secret, sha512.New, data)
}

func verifyHMACSHA512(secret []byte, data, sig []byte) (bool, error) {
	return verifyHMAC(secret, sha512.New, data, sig)
}

func signHMAC(secret []byte, hashFunc func() hash.Hash, data []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("httpsig: empty HMAC secret")
	}
	mac := hmac.New(hashFunc, secret)
	mac.Write(data)
	return mac.Sum(nil), nil
}

func verifyHMAC(secret []byte, hashFunc func() hash.Hash, data, sig []byte) (bool, error) {
	expected, err := signHMAC(secret, hashFunc, data)
	if err != nil {
		return false, err
	}
	return hmac.Equal(sig, expected), nil
}
