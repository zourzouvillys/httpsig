package httpsig

import "net/http"

// VerifyMiddleware is HTTP server middleware that verifies request signatures.
// Requests with valid signatures are passed to the next handler with the
// VerifyResult stored in the request context. Invalid or missing signatures
// receive a 401 response (customizable via OnError).
type VerifyMiddleware struct {
	// Provider resolves key IDs to verifying keys.
	Provider KeyProvider

	// Options controls verification behavior (required components, max age, etc.).
	Options *VerifyOptions

	// OnError handles verification failures. If nil, responds with 401 Unauthorized.
	OnError func(w http.ResponseWriter, r *http.Request, err error)
}

// Wrap returns an http.Handler that verifies signatures before calling next.
func (m *VerifyMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := &RequestMessage{Req: r}
		// If options have a NonceChecker but no Context, inject the request context.
		opts := m.Options
		if opts != nil && opts.NonceChecker != nil && opts.Context == nil {
			cp := *opts
			cp.Context = r.Context()
			opts = &cp
		}
		result, err := VerifyMessage(msg, m.Provider, opts, nil)
		if err != nil {
			if m.OnError != nil {
				m.OnError(w, r, err)
			} else {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			}
			return
		}

		ctx := withVerifyResult(r.Context(), result)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireSignature is a convenience constructor for VerifyMiddleware.
// It returns middleware that verifies request signatures using the given
// provider and options, responding with 401 on failure.
func RequireSignature(provider KeyProvider, opts *VerifyOptions) func(http.Handler) http.Handler {
	m := &VerifyMiddleware{Provider: provider, Options: opts}
	return m.Wrap
}
