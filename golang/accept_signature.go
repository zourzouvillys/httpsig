package httpsig

import (
	"fmt"
	"sort"
)

// SignatureRequirements defines what a valid signature must contain.
// Used for both verification filtering and Accept-Signature negotiation (RFC 9421 §5).
type SignatureRequirements struct {
	// Components lists the component identifiers that must be covered by the signature.
	Components []ComponentIdentifier

	// KeyID, if non-empty, requires the signature to use this key ID.
	KeyID string

	// Algorithm, if non-empty, requires the signature to use this algorithm.
	Algorithm Algorithm

	// Tag, if non-empty, requires the signature to have this tag parameter.
	Tag string

	// RequireCreated, if true, indicates that the signature must have a created parameter.
	RequireCreated bool

	// RequireExpires, if true, indicates that the signature must have an expires parameter.
	RequireExpires bool
}

// BuildAcceptSignature serializes requirements as an Accept-Signature header value.
// Each entry maps a label to its requirements. The output is a Structured Field Values
// Dictionary where each member is an inner list of component identifiers with parameters.
func BuildAcceptSignature(entries map[string]SignatureRequirements) string {
	// Sort keys for deterministic output.
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	members := make([]SFVDictMember, 0, len(entries))
	for _, label := range keys {
		req := entries[label]
		members = append(members, SFVDictMember{
			Key:       label,
			InnerList: requirementsToInnerList(req),
		})
	}
	return SerializeDictionary(members)
}

// requirementsToInnerList converts a SignatureRequirements to an SFVInnerList
// for serialization in the Accept-Signature header.
func requirementsToInnerList(req SignatureRequirements) *SFVInnerList {
	items := make([]SFVItem, len(req.Components))
	for i, c := range req.Components {
		items[i] = SFVItem{
			Value:  c.Name,
			Params: c.Params,
		}
	}

	params := NewSFVParams()
	if req.KeyID != "" {
		params.Set("keyid", req.KeyID)
	}
	if req.Algorithm != "" {
		params.Set("alg", string(req.Algorithm))
	}
	if req.RequireCreated {
		params.Set("created", true)
	}
	if req.RequireExpires {
		params.Set("expires", true)
	}
	if req.Tag != "" {
		params.Set("tag", req.Tag)
	}

	var p *SFVParams
	if params.Len() > 0 {
		p = params
	}

	return &SFVInnerList{
		Items:  items,
		Params: p,
	}
}

// ParseAcceptSignature parses an Accept-Signature header value into a map of
// label to SignatureRequirements. Returns an error if the header cannot be parsed.
func ParseAcceptSignature(headerValue string) (map[string]SignatureRequirements, error) {
	members, err := ParseDictionary(headerValue)
	if err != nil {
		return nil, fmt.Errorf("httpsig: malformed Accept-Signature: %w", err)
	}

	result := make(map[string]SignatureRequirements, len(members))
	for _, m := range members {
		if m.InnerList == nil {
			continue
		}

		components, err := parseComponentsFromInnerList(m.InnerList)
		if err != nil {
			return nil, fmt.Errorf("httpsig: invalid components in %q: %w", m.Key, err)
		}

		req := SignatureRequirements{
			Components: components,
		}

		if m.InnerList.Params != nil {
			if v, ok := m.InnerList.Params.Get("keyid"); ok {
				if s, ok := v.(string); ok {
					req.KeyID = s
				}
			}
			if v, ok := m.InnerList.Params.Get("alg"); ok {
				if s, ok := v.(string); ok {
					req.Algorithm = Algorithm(s)
				}
			}
			if v, ok := m.InnerList.Params.Get("tag"); ok {
				if s, ok := v.(string); ok {
					req.Tag = s
				}
			}
			if _, ok := m.InnerList.Params.Get("created"); ok {
				req.RequireCreated = true
			}
			if _, ok := m.InnerList.Params.Get("expires"); ok {
				req.RequireExpires = true
			}
		}

		result[m.Key] = req
	}

	return result, nil
}

// ToSignatureParameters converts requirements to SignatureParameters suitable for signing.
// The created, expires, and nonce values are provided by the caller since they are
// per-signature rather than per-requirement.
func (r SignatureRequirements) ToSignatureParameters(created *int64, expires *int64, nonce *string) SignatureParameters {
	// Copy components to avoid sharing the slice.
	components := make([]ComponentIdentifier, len(r.Components))
	copy(components, r.Components)

	var tag *string
	if r.Tag != "" {
		tag = StringPtr(r.Tag)
	}

	return SignatureParameters{
		Components: components,
		KeyID:      r.KeyID,
		Algorithm:  r.Algorithm,
		Created:    created,
		Expires:    expires,
		Nonce:      nonce,
		Tag:        tag,
	}
}
