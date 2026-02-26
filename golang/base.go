package httpsig

import (
	"fmt"
	"strings"
)

// SignatureParameters defines what to sign: the covered components plus metadata.
// Note: the Algorithm field controls whether "alg" appears in the serialized signature
// parameters. It does NOT control which algorithm the signing key uses. Leave it empty
// to omit "alg" from the signature parameters (the key determines the algorithm).
type SignatureParameters struct {
	Components []ComponentIdentifier
	Algorithm  Algorithm // if set, included as "alg" in signature params
	KeyID      string
	Created    *int64
	Expires    *int64
	Nonce      *string
	Tag        *string
}

// BuildSignatureBase constructs the signature base string per RFC 9421 Section 2.5.
// The reqMsg parameter is only needed for response signatures with ;req components.
func BuildSignatureBase(msg Message, params SignatureParameters, reqMsg Message) ([]byte, string, error) {
	if err := validateComponents(params.Components); err != nil {
		return nil, "", err
	}

	var base strings.Builder

	for _, c := range params.Components {
		value, err := extractComponent(c, msg, reqMsg)
		if err != nil {
			return nil, "", err
		}
		// Each component line: "<component-id>": <value>\n
		base.WriteString(serializeComponentID(c))
		base.WriteString(": ")
		base.WriteString(value)
		base.WriteByte('\n')
	}

	// Build the @signature-params line
	sfvParams := buildSFVParams(params)
	sigParamsValue := SerializeSignatureParams(params.Components, sfvParams)

	base.WriteString("\"@signature-params\": ")
	base.WriteString(sigParamsValue)

	return []byte(base.String()), sigParamsValue, nil
}

func buildSFVParams(params SignatureParameters) *SFVParams {
	// Parameter ordering follows the convention used in RFC 9421 Appendix B:
	// created, expires, keyid, alg, nonce, tag
	p := NewSFVParams()
	if params.Created != nil {
		p.Set("created", *params.Created)
	}
	if params.Expires != nil {
		p.Set("expires", *params.Expires)
	}
	if params.KeyID != "" {
		p.Set("keyid", params.KeyID)
	}
	if params.Algorithm != "" {
		p.Set("alg", string(params.Algorithm))
	}
	if params.Nonce != nil {
		p.Set("nonce", *params.Nonce)
	}
	if params.Tag != nil {
		p.Set("tag", *params.Tag)
	}
	return p
}

func validateComponents(components []ComponentIdentifier) error {
	seen := make(map[string]bool)
	for _, c := range components {
		key := serializeComponentID(c)
		if seen[key] {
			return fmt.Errorf("%w: %s", ErrDuplicateComponent, key)
		}
		seen[key] = true
	}
	return nil
}

// Int64Ptr returns a pointer to the given int64. Convenience for building SignatureParameters.
func Int64Ptr(v int64) *int64 { return &v }

// StringPtr returns a pointer to the given string. Convenience for building SignatureParameters.
func StringPtr(v string) *string { return &v }
