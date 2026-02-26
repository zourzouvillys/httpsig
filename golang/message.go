package httpsig

import (
	"net/http"
	"net/url"
)

// Message is a minimal view of an HTTP message for signature operations.
// Implementations should handle both requests and responses.
type Message interface {
	IsRequest() bool
	Method() string
	URL() *url.URL
	StatusCode() int
	HeaderValues(name string) []string
}

// RequestMessage wraps an *http.Request as a Message.
type RequestMessage struct {
	Req *http.Request
}

func (m *RequestMessage) IsRequest() bool { return true }
func (m *RequestMessage) Method() string  { return m.Req.Method }
func (m *RequestMessage) URL() *url.URL {
	u := m.Req.URL
	if u.Host == "" && m.Req.Host != "" {
		// Server-side request: URL only has path+query, reconstruct full URL
		clone := *u
		clone.Host = m.Req.Host
		clone.Scheme = "http"
		if m.Req.TLS != nil {
			clone.Scheme = "https"
		}
		return &clone
	}
	return u
}
func (m *RequestMessage) StatusCode() int { return 0 }
func (m *RequestMessage) HeaderValues(name string) []string {
	return m.Req.Header.Values(name)
}

// ResponseMessage wraps an *http.Response as a Message, with access to the
// associated request for request-bound signatures.
type ResponseMessage struct {
	Resp *http.Response
	Req  *http.Request
}

func (m *ResponseMessage) IsRequest() bool              { return false }
func (m *ResponseMessage) Method() string               { return m.Req.Method }
func (m *ResponseMessage) URL() *url.URL                { return m.Req.URL }
func (m *ResponseMessage) StatusCode() int              { return m.Resp.StatusCode }
func (m *ResponseMessage) HeaderValues(name string) []string {
	return m.Resp.Header.Values(name)
}

// RawMessage is a hand-constructed Message for testing and non-standard use.
type RawMessage struct {
	IsReq      bool
	Meth       string
	TargetURI  *url.URL
	Status     int
	Headers    http.Header
}

func (m *RawMessage) IsRequest() bool              { return m.IsReq }
func (m *RawMessage) Method() string               { return m.Meth }
func (m *RawMessage) URL() *url.URL                { return m.TargetURI }
func (m *RawMessage) StatusCode() int              { return m.Status }
func (m *RawMessage) HeaderValues(name string) []string {
	return m.Headers.Values(name)
}
