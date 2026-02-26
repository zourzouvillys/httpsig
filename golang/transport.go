package httpsig

import (
	"net/http"
	"time"
)

// Transport is an http.RoundTripper that signs outgoing requests.
// It wraps a base transport and adds Signature-Input and Signature headers.
type Transport struct {
	// Base is the underlying RoundTripper. If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// Key is the signing key for outgoing requests.
	Key SigningKey

	// Label is the signature label (e.g. "sig1"). Defaults to "sig1".
	Label string

	// Params builds the SignatureParameters for each request. If nil, a default
	// set of components is used: @method, @path, @authority.
	Params func(*http.Request) SignatureParameters
}

var _ http.RoundTripper = (*Transport)(nil)

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) label() string {
	if t.Label != "" {
		return t.Label
	}
	return "sig1"
}

func (t *Transport) params(req *http.Request) SignatureParameters {
	if t.Params != nil {
		return t.Params(req)
	}
	return SignatureParameters{
		Components: []ComponentIdentifier{
			Component("@method"),
			Component("@path"),
			Component("@authority"),
		},
		KeyID:   t.Key.KeyID(),
		Created: Int64Ptr(time.Now().Unix()),
	}
}

// RoundTrip signs the request and delegates to the base transport.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the caller's request
	signed := req.Clone(req.Context())

	msg := &RequestMessage{Req: signed}
	params := t.params(req)

	result, err := SignMessage(msg, t.label(), params, t.Key, nil)
	if err != nil {
		return nil, err
	}

	signed.Header.Set("Signature-Input", SignatureInputHeader(result))
	signed.Header.Set("Signature", SignatureHeader(result))

	return t.base().RoundTrip(signed)
}
