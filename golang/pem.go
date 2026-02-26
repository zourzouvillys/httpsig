package httpsig

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
)

// pkcs8PrivateKey is the ASN.1 structure for PKCS#8
type pkcs8PrivateKey struct {
	Version    int
	Algorithm  asn1.RawValue
	PrivateKey []byte
}

// rsaPrivateKeyASN1 is the ASN.1 structure for an RSA private key (PKCS#1)
type rsaPrivateKeyASN1 struct {
	Version int
	N       *big.Int
	E       int
	D       *big.Int
	P       *big.Int
	Q       *big.Int
	Dp      *big.Int
	Dq      *big.Int
	Qinv    *big.Int
}

// ParseRSAPSSPrivateKeyPEM parses a PKCS#8 PEM encoded RSA-PSS private key.
// Go's standard library doesn't handle the RSA-PSS OID (1.2.840.113549.1.1.10),
// so we parse the ASN.1 manually and extract the underlying RSA key.
func ParseRSAPSSPrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// First try standard parsing in case Go version supports it
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
	}

	// Fall back to manual ASN.1 parsing for RSA-PSS keys
	var pkcs8 pkcs8PrivateKey
	if _, err := asn1.Unmarshal(block.Bytes, &pkcs8); err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8: %w", err)
	}

	var rsaASN1 rsaPrivateKeyASN1
	if _, err := asn1.Unmarshal(pkcs8.PrivateKey, &rsaASN1); err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: rsaASN1.N,
			E: rsaASN1.E,
		},
		D: rsaASN1.D,
		Primes: []*big.Int{
			rsaASN1.P,
			rsaASN1.Q,
		},
	}
	key.Precompute()

	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("RSA key validation failed: %w", err)
	}

	return key, nil
}
