package httpsig

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// ComponentIdentifier identifies a component to include in a signature base.
type ComponentIdentifier struct {
	Name   string     // lowercase header name or derived component (e.g. "@method", "content-type")
	Params *SFVParams // optional parameters (sf, key, bs, req, name)
}

// Component creates a ComponentIdentifier with no parameters.
func Component(name string) ComponentIdentifier {
	return ComponentIdentifier{Name: strings.ToLower(name)}
}

// ComponentWithParams creates a ComponentIdentifier with the given parameters.
func ComponentWithParams(name string, params *SFVParams) ComponentIdentifier {
	return ComponentIdentifier{Name: strings.ToLower(name), Params: params}
}

// QueryParam creates a @query-param component identifier for the named parameter.
func QueryParam(name string) ComponentIdentifier {
	p := NewSFVParams()
	p.Set("name", name)
	return ComponentIdentifier{Name: "@query-param", Params: p}
}

// ComponentWithKey creates a component identifier with the ;key parameter for
// extracting a single member from a Dictionary Structured Field header.
// For example, ComponentWithKey("signature", "sig1") extracts the "sig1" entry
// from the Signature dictionary header.
func ComponentWithKey(name string, key string) ComponentIdentifier {
	p := NewSFVParams()
	p.Set("key", key)
	return ComponentIdentifier{Name: strings.ToLower(name), Params: p}
}

// ComponentReq creates a component identifier with the ;req flag for request-bound
// response signatures.
func ComponentReq(name string) ComponentIdentifier {
	p := NewSFVParams()
	p.Set("req", true)
	return ComponentIdentifier{Name: strings.ToLower(name), Params: p}
}

// isDerived returns true if this is a derived component (starts with @).
func (c ComponentIdentifier) isDerived() bool {
	return len(c.Name) > 0 && c.Name[0] == '@'
}

// hasParam checks if a parameter is set.
func (c ComponentIdentifier) hasParam(key string) bool {
	if c.Params == nil {
		return false
	}
	_, ok := c.Params.Get(key)
	return ok
}

// paramString returns a string parameter value or empty string.
func (c ComponentIdentifier) paramString(key string) string {
	if c.Params == nil {
		return ""
	}
	v, ok := c.Params.Get(key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// extractComponent extracts the value of a component from a message.
// For request-bound components (;req), reqMsg is the associated request.
func extractComponent(c ComponentIdentifier, msg Message, reqMsg Message) (string, error) {
	// If ;req is set, extract from the request message
	if c.hasParam("req") {
		if reqMsg == nil {
			return "", fmt.Errorf("%w: ;req specified but no request message available", ErrMissingComponent)
		}
		// Build a component without the ;req param to extract from the request
		stripped := ComponentIdentifier{Name: c.Name}
		if c.Params != nil {
			sp := NewSFVParams()
			for _, k := range c.Params.Keys {
				if k != "req" {
					sp.Set(k, c.Params.Values[k])
				}
			}
			if sp.Len() > 0 {
				stripped.Params = sp
			}
		}
		return extractComponent(stripped, reqMsg, nil)
	}

	if c.isDerived() {
		return extractDerived(c, msg)
	}
	return extractHeader(c, msg)
}

func extractDerived(c ComponentIdentifier, msg Message) (string, error) {
	switch c.Name {
	case "@method":
		if !msg.IsRequest() {
			return "", fmt.Errorf("%w: @method on response", ErrMissingComponent)
		}
		return strings.ToUpper(msg.Method()), nil

	case "@target-uri":
		if !msg.IsRequest() {
			return "", fmt.Errorf("%w: @target-uri on response", ErrMissingComponent)
		}
		return msg.URL().String(), nil

	case "@authority":
		if !msg.IsRequest() {
			return "", fmt.Errorf("%w: @authority on response", ErrMissingComponent)
		}
		return extractAuthority(msg.URL()), nil

	case "@scheme":
		if !msg.IsRequest() {
			return "", fmt.Errorf("%w: @scheme on response", ErrMissingComponent)
		}
		return strings.ToLower(msg.URL().Scheme), nil

	case "@request-target":
		if !msg.IsRequest() {
			return "", fmt.Errorf("%w: @request-target on response", ErrMissingComponent)
		}
		return extractRequestTarget(msg.URL()), nil

	case "@path":
		if !msg.IsRequest() {
			return "", fmt.Errorf("%w: @path on response", ErrMissingComponent)
		}
		path := msg.URL().Path
		if path == "" {
			path = "/"
		}
		return path, nil

	case "@query":
		if !msg.IsRequest() {
			return "", fmt.Errorf("%w: @query on response", ErrMissingComponent)
		}
		return extractQuery(msg.URL()), nil

	case "@query-param":
		if !msg.IsRequest() {
			return "", fmt.Errorf("%w: @query-param on response", ErrMissingComponent)
		}
		name := c.paramString("name")
		if name == "" {
			return "", fmt.Errorf("%w: @query-param requires ;name parameter", ErrMissingComponent)
		}
		return extractQueryParam(msg.URL(), name)

	case "@status":
		if msg.IsRequest() {
			return "", fmt.Errorf("%w: @status on request", ErrMissingComponent)
		}
		return fmt.Sprintf("%d", msg.StatusCode()), nil

	default:
		return "", fmt.Errorf("%w: unknown derived component %s", ErrMissingComponent, c.Name)
	}
}

func extractHeader(c ComponentIdentifier, msg Message) (string, error) {
	if c.hasParam("sf") {
		return extractHeaderSF(c, msg)
	}
	if c.hasParam("bs") {
		return extractHeaderBS(c, msg)
	}
	if c.hasParam("key") {
		return extractHeaderKey(c, msg)
	}

	values := msg.HeaderValues(c.Name)
	if len(values) == 0 {
		return "", fmt.Errorf("%w: header %q not present", ErrMissingComponent, c.Name)
	}

	// Combine multiple header values with ", " per RFC 9421 Section 2.1
	var trimmed []string
	for _, v := range values {
		trimmed = append(trimmed, strings.TrimSpace(v))
	}
	return strings.Join(trimmed, ", "), nil
}

// extractHeaderSF handles ;sf (structured field) parameter.
// For our purposes, we parse and re-serialize the header value.
func extractHeaderSF(c ComponentIdentifier, msg Message) (string, error) {
	values := msg.HeaderValues(c.Name)
	if len(values) == 0 {
		return "", fmt.Errorf("%w: header %q not present", ErrMissingComponent, c.Name)
	}
	// Re-join and return as-is. Full SFV re-serialization is complex.
	// For RFC 9421 compliance, the value should be parsed as SFV and re-serialized.
	// For now, we trim and join which handles the common case.
	var trimmed []string
	for _, v := range values {
		trimmed = append(trimmed, strings.TrimSpace(v))
	}
	return strings.Join(trimmed, ", "), nil
}

// extractHeaderBS handles ;bs (byte sequence) parameter.
func extractHeaderBS(c ComponentIdentifier, msg Message) (string, error) {
	values := msg.HeaderValues(c.Name)
	if len(values) == 0 {
		return "", fmt.Errorf("%w: header %q not present", ErrMissingComponent, c.Name)
	}
	// ;bs wraps each header field value in SFV Binary Sequence encoding
	var encoded []string
	for _, v := range values {
		encoded = append(encoded, ":"+base64.StdEncoding.EncodeToString([]byte(strings.TrimSpace(v)))+":")
	}
	return strings.Join(encoded, ", "), nil
}

// extractHeaderKey handles ;key for Dictionary Structured Fields.
func extractHeaderKey(c ComponentIdentifier, msg Message) (string, error) {
	key := c.paramString("key")
	if key == "" {
		return "", fmt.Errorf("%w: ;key parameter is empty", ErrMissingComponent)
	}
	values := msg.HeaderValues(c.Name)
	if len(values) == 0 {
		return "", fmt.Errorf("%w: header %q not present", ErrMissingComponent, c.Name)
	}
	combined := strings.Join(values, ", ")
	members, err := ParseDictionary(combined)
	if err != nil {
		return "", fmt.Errorf("%w: cannot parse %q as dictionary: %v", ErrMissingComponent, c.Name, err)
	}
	for _, m := range members {
		if m.Key == key {
			if m.InnerList != nil {
				return serializeInnerList(m.InnerList), nil
			}
			if m.Item != nil {
				result := serializeBareItem(m.Item.Value)
				if m.Item.Params != nil && m.Item.Params.Len() > 0 {
					result += serializeParams(m.Item.Params)
				}
				return result, nil
			}
		}
	}
	return "", fmt.Errorf("%w: key %q not found in dictionary header %q", ErrMissingComponent, key, c.Name)
}

func extractAuthority(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		return strings.ToLower(host)
	}
	// Omit default ports
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		return strings.ToLower(host)
	}
	return strings.ToLower(host) + ":" + port
}

func extractRequestTarget(u *url.URL) string {
	path := u.RequestURI()
	if path == "" {
		return "/"
	}
	return path
}

func extractQuery(u *url.URL) string {
	if u.RawQuery == "" && u.ForceQuery {
		return "?"
	}
	if u.RawQuery == "" {
		return "?"
	}
	return "?" + u.RawQuery
}

func extractQueryParam(u *url.URL, name string) (string, error) {
	values := u.Query()[name]
	if len(values) == 0 {
		return "", fmt.Errorf("%w: query parameter %q not present", ErrMissingComponent, name)
	}
	// RFC 9421: use the first value
	return values[0], nil
}
