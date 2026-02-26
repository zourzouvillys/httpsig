package httpsig

import "fmt"

// SignResult holds the output of a signing operation.
type SignResult struct {
	// Label is the signature label (e.g. "sig1").
	Label string
	// SignatureInput is the value to set for the Signature-Input header entry.
	SignatureInput string
	// Signature is the base64-encoded signature value for the Signature header entry.
	Signature []byte
}

// SignMessage signs a message and returns the Signature-Input and Signature values.
// The label identifies this signature (e.g. "sig1").
// The reqMsg parameter is only needed for response signatures with ;req components.
func SignMessage(msg Message, label string, params SignatureParameters, key SigningKey, reqMsg Message) (*SignResult, error) {
	base, sigInput, err := BuildSignatureBase(msg, params, reqMsg)
	if err != nil {
		return nil, fmt.Errorf("building signature base: %w", err)
	}

	sig, err := key.Sign(base)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	return &SignResult{
		Label:          label,
		SignatureInput: sigInput,
		Signature:      sig,
	}, nil
}

// SignatureInputHeader returns the full Signature-Input header value for one or more signatures.
func SignatureInputHeader(results ...*SignResult) string {
	members := make([]SFVDictMember, len(results))
	for i, r := range results {
		members[i] = SFVDictMember{
			Key:  r.Label,
			Item: &SFVItem{Value: Token(r.SignatureInput)},
		}
	}
	return SerializeDictionary(members)
}

// SignatureHeader returns the full Signature header value for one or more signatures.
func SignatureHeader(results ...*SignResult) string {
	members := make([]SFVDictMember, len(results))
	for i, r := range results {
		members[i] = SFVDictMember{
			Key:  r.Label,
			Item: &SFVItem{Value: r.Signature},
		}
	}
	return SerializeDictionary(members)
}
