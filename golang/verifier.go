package httpsig

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// VerifyOptions controls signature verification behavior.
type VerifyOptions struct {
	// RequiredComponents specifies components that must be in the signature's
	// covered components. Verification fails if any are missing.
	RequiredComponents []ComponentIdentifier

	// Requirements, if set, provides full signature requirements for filtering.
	// It takes precedence over RequiredComponents for the required-components check,
	// and additionally filters by KeyID, Algorithm, and Tag when those fields are set.
	// When nil, RequiredComponents is used as before (backward-compatible).
	Requirements *SignatureRequirements

	// MaxAge is the maximum allowed age of a signature based on the "created" parameter.
	// Zero means no age check.
	MaxAge time.Duration

	// MaxClockSkew is the maximum allowed forward clock skew for the "created" parameter.
	// Signatures with created > now + MaxClockSkew are rejected.
	// Zero means no future-dating check.
	MaxClockSkew time.Duration

	// RejectExpired controls whether expired signatures (based on "expires") are rejected.
	// Defaults to true.
	RejectExpired *bool

	// Now overrides the current time for testing. If nil, time.Now() is used.
	Now func() time.Time

	// RequiredLabel specifies a specific signature label to verify. If empty,
	// verifies the first signature that has a matching key.
	RequiredLabel string

	// NonceChecker, if set, is called after cryptographic verification succeeds
	// for signatures that include a nonce parameter. If it returns an error,
	// verification fails. This allows callers to enforce nonce uniqueness
	// (replay protection). If the signature has no nonce, the checker is not called.
	NonceChecker func(ctx context.Context, nonce string, keyID string, algorithm Algorithm) error

	// Context provides a context for callbacks such as NonceChecker.
	// If nil, context.Background() is used.
	Context context.Context
}

func (o *VerifyOptions) now() time.Time {
	if o != nil && o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *VerifyOptions) rejectExpired() bool {
	if o != nil && o.RejectExpired != nil {
		return *o.RejectExpired
	}
	return true
}

// VerifyResult holds information about a successfully verified signature.
type VerifyResult struct {
	// Label is the signature label that was verified.
	Label string
	// KeyID is the key ID from the signature parameters.
	KeyID string
	// Algorithm is the algorithm from the signature parameters.
	Algorithm Algorithm
	// Components are the covered components.
	Components []ComponentIdentifier
	// Created is the creation timestamp, if present.
	Created *int64
	// Expires is the expiration timestamp, if present.
	Expires *int64
	// Nonce is the nonce string from the signature parameters, if present.
	Nonce *string
}

// VerifyMessage verifies a signature on a message.
// It parses the Signature-Input and Signature headers, reconstructs the signature base,
// and verifies the signature using the key from the provider.
func VerifyMessage(msg Message, provider KeyProvider, opts *VerifyOptions, reqMsg Message) (*VerifyResult, error) {
	// Parse Signature-Input header
	sigInputValues := msg.HeaderValues("signature-input")
	if len(sigInputValues) == 0 {
		return nil, ErrMissingSignature
	}
	sigInputStr := joinHeaderValues(sigInputValues)

	sigInputDict, err := ParseDictionary(sigInputStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedSignatureInput, err)
	}

	// Parse Signature header
	sigValues := msg.HeaderValues("signature")
	if len(sigValues) == 0 {
		return nil, ErrMissingSignature
	}
	sigStr := joinHeaderValues(sigValues)

	sigDict, err := ParseDictionary(sigStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedSignature, err)
	}

	// Build lookup for signatures
	sigMap := make(map[string][]byte)
	for _, m := range sigDict {
		if m.Item != nil {
			if bs, ok := m.Item.Value.([]byte); ok {
				sigMap[m.Key] = bs
			}
		}
	}

	// Try each signature input entry
	for _, member := range sigInputDict {
		label := member.Key

		// If a specific label is required, skip others
		if opts != nil && opts.RequiredLabel != "" && label != opts.RequiredLabel {
			continue
		}

		if member.InnerList == nil {
			continue
		}

		// Parse components from inner list
		components, err := parseComponentsFromInnerList(member.InnerList)
		if err != nil {
			continue
		}

		// Extract parameters
		sigParams, err := parseSignatureParams(member.InnerList.Params, components)
		if err != nil {
			continue
		}

		// Check required components and requirements filtering
		if opts != nil {
			if opts.Requirements != nil {
				// Use Requirements for component and metadata filtering.
				if !hasRequiredComponents(sigParams.Components, opts.Requirements.Components) {
					continue
				}
				if opts.Requirements.KeyID != "" && sigParams.KeyID != opts.Requirements.KeyID {
					continue
				}
				if opts.Requirements.Algorithm != "" && sigParams.Algorithm != opts.Requirements.Algorithm {
					continue
				}
				if opts.Requirements.Tag != "" {
					if sigParams.Tag == nil || *sigParams.Tag != opts.Requirements.Tag {
						continue
					}
				}
			} else if !hasRequiredComponents(sigParams.Components, opts.RequiredComponents) {
				continue
			}
		}

		// Check time constraints
		if err := checkTimeConstraints(sigParams, opts); err != nil {
			continue
		}

		// Look up the signature bytes
		sigBytes, ok := sigMap[label]
		if !ok {
			continue
		}

		// Resolve the key
		key, err := provider(sigParams.KeyID, sigParams.Algorithm)
		if err != nil {
			continue
		}

		// If algorithm was specified in the input, it must match the key
		if sigParams.Algorithm != "" && key.Algorithm() != sigParams.Algorithm {
			continue
		}

		// Build signature base and verify
		base, _, err := BuildSignatureBase(msg, sigParams, reqMsg)
		if err != nil {
			continue
		}

		valid, err := key.Verify(base, sigBytes)
		if err != nil || !valid {
			continue
		}

		// Call NonceChecker if configured and a nonce is present
		if opts != nil && opts.NonceChecker != nil && sigParams.Nonce != nil {
			ctx := opts.Context
			if ctx == nil {
				ctx = context.Background()
			}
			if err := opts.NonceChecker(ctx, *sigParams.Nonce, key.KeyID(), key.Algorithm()); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
			}
		}

		return &VerifyResult{
			Label:      label,
			KeyID:      key.KeyID(),
			Algorithm:  key.Algorithm(),
			Components: sigParams.Components,
			Created:    sigParams.Created,
			Expires:    sigParams.Expires,
			Nonce:      sigParams.Nonce,
		}, nil
	}

	return nil, ErrInvalidSignature
}

func parseComponentsFromInnerList(il *SFVInnerList) ([]ComponentIdentifier, error) {
	var components []ComponentIdentifier
	for _, item := range il.Items {
		name, ok := item.Value.(string)
		if !ok {
			return nil, fmt.Errorf("component identifier must be a string")
		}
		components = append(components, ComponentIdentifier{
			Name:   name,
			Params: item.Params,
		})
	}
	return components, nil
}

func parseSignatureParams(params *SFVParams, components []ComponentIdentifier) (SignatureParameters, error) {
	sp := SignatureParameters{
		Components: components,
	}
	if params == nil {
		return sp, nil
	}

	if v, ok := params.Get("created"); ok {
		if n, ok := v.(int64); ok {
			sp.Created = &n
		}
	}
	if v, ok := params.Get("expires"); ok {
		if n, ok := v.(int64); ok {
			sp.Expires = &n
		}
	}
	if v, ok := params.Get("nonce"); ok {
		if s, ok := v.(string); ok {
			sp.Nonce = &s
		}
	}
	if v, ok := params.Get("alg"); ok {
		if s, ok := v.(string); ok {
			sp.Algorithm = Algorithm(s)
		}
	}
	if v, ok := params.Get("keyid"); ok {
		if s, ok := v.(string); ok {
			sp.KeyID = s
		}
	}
	if v, ok := params.Get("tag"); ok {
		if s, ok := v.(string); ok {
			sp.Tag = &s
		}
	}
	return sp, nil
}

func hasRequiredComponents(have, required []ComponentIdentifier) bool {
	if len(required) == 0 {
		return true
	}
	haveSet := make(map[string]bool)
	for _, c := range have {
		haveSet[serializeComponentID(c)] = true
	}
	for _, c := range required {
		if !haveSet[serializeComponentID(c)] {
			return false
		}
	}
	return true
}

func checkTimeConstraints(params SignatureParameters, opts *VerifyOptions) error {
	if opts == nil {
		return nil
	}

	now := opts.now()

	if params.Created != nil && opts.MaxAge > 0 {
		created := time.Unix(*params.Created, 0)
		if now.Sub(created) > opts.MaxAge {
			return ErrSignatureExpired
		}
	}

	if params.Created != nil && opts.MaxClockSkew > 0 {
		created := time.Unix(*params.Created, 0)
		if created.Sub(now) > opts.MaxClockSkew {
			return ErrSignatureFutureDated
		}
	}

	if params.Expires != nil && opts.rejectExpired() {
		expires := time.Unix(*params.Expires, 0)
		if now.After(expires) {
			return ErrSignatureExpired
		}
	}

	return nil
}

func joinHeaderValues(values []string) string {
	return strings.Join(values, ", ")
}
