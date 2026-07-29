package authn

import "context"

type ctxKey int

const principalKey ctxKey = 1

// WithPrincipal attaches an authenticated principal to ctx.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFromContext returns the authenticated principal when present.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}
