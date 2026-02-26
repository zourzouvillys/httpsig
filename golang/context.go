package httpsig

import "context"

type contextKey struct{}

// withVerifyResult stores a VerifyResult in the context.
func withVerifyResult(ctx context.Context, result *VerifyResult) context.Context {
	return context.WithValue(ctx, contextKey{}, result)
}

// VerifyResultFromContext retrieves the VerifyResult stored by the
// verification middleware. Returns nil if no result is present.
func VerifyResultFromContext(ctx context.Context) *VerifyResult {
	v, _ := ctx.Value(contextKey{}).(*VerifyResult)
	return v
}
