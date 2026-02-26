package httpsig

import (
	"net/http"
	"net/url"
	"testing"
)

func testRequestMessage() Message {
	u, _ := url.Parse("https://example.com/foo?param=Value&Pet=dog")
	return &RawMessage{
		IsReq:     true,
		Meth:      "POST",
		TargetURI: u,
		Headers: http.Header{
			"Host":           {"example.com"},
			"Date":           {"Tue, 20 Apr 2021 02:07:55 GMT"},
			"Content-Type":   {"application/json"},
			"Content-Digest": {"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
			"Content-Length": {"18"},
		},
	}
}

func TestExtractDerivedComponents(t *testing.T) {
	msg := testRequestMessage()

	tests := []struct {
		component ComponentIdentifier
		want      string
	}{
		{Component("@method"), "POST"},
		{Component("@path"), "/foo"},
		{Component("@query"), "?param=Value&Pet=dog"},
		{Component("@authority"), "example.com"},
		{Component("@scheme"), "https"},
		{Component("@target-uri"), "https://example.com/foo?param=Value&Pet=dog"},
		{Component("@request-target"), "/foo?param=Value&Pet=dog"},
		{QueryParam("Pet"), "dog"},
		{QueryParam("param"), "Value"},
	}

	for _, tt := range tests {
		t.Run(tt.component.Name, func(t *testing.T) {
			got, err := extractComponent(tt.component, msg, nil)
			if err != nil {
				t.Fatalf("extractComponent: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractHeaders(t *testing.T) {
	msg := testRequestMessage()

	tests := []struct {
		name string
		want string
	}{
		{"content-type", "application/json"},
		{"date", "Tue, 20 Apr 2021 02:07:55 GMT"},
		{"content-length", "18"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractComponent(Component(tt.name), msg, nil)
			if err != nil {
				t.Fatalf("extractComponent: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractMultiValueHeader(t *testing.T) {
	u, _ := url.Parse("https://example.org/demo")
	msg := &RawMessage{
		IsReq:     true,
		Meth:      "GET",
		TargetURI: u,
		Headers: http.Header{
			"Accept": {"application/json", "*/*"},
		},
	}

	got, err := extractComponent(Component("accept"), msg, nil)
	if err != nil {
		t.Fatalf("extractComponent: %v", err)
	}
	want := "application/json, */*"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestExtractMissingHeader(t *testing.T) {
	msg := testRequestMessage()
	_, err := extractComponent(Component("x-not-present"), msg, nil)
	if err == nil {
		t.Error("expected error for missing header")
	}
}

func TestExtractStatusOnRequest(t *testing.T) {
	msg := testRequestMessage()
	_, err := extractComponent(Component("@status"), msg, nil)
	if err == nil {
		t.Error("expected error for @status on request")
	}
}

func TestExtractMethodOnResponse(t *testing.T) {
	msg := &RawMessage{
		IsReq:  false,
		Status: 200,
		Headers: http.Header{
			"Content-Type": {"application/json"},
		},
	}
	_, err := extractComponent(Component("@method"), msg, nil)
	if err == nil {
		t.Error("expected error for @method on response")
	}
}

func TestExtractStatus(t *testing.T) {
	msg := &RawMessage{
		IsReq:  false,
		Status: 200,
		Headers: http.Header{
			"Content-Type": {"application/json"},
		},
	}
	got, err := extractComponent(Component("@status"), msg, nil)
	if err != nil {
		t.Fatalf("extractComponent: %v", err)
	}
	if got != "200" {
		t.Errorf("got %q, want %q", got, "200")
	}
}

func TestExtractQueryParamMissing(t *testing.T) {
	msg := testRequestMessage()
	_, err := extractComponent(QueryParam("missing"), msg, nil)
	if err == nil {
		t.Error("expected error for missing query param")
	}
}
