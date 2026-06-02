package core

import "context"

type apiKeyCtxKey struct{}

func WithAPIKey(ctx context.Context, key *APIKey) context.Context {
	return context.WithValue(ctx, apiKeyCtxKey{}, key)
}

func APIKeyFromContext(ctx context.Context) (*APIKey, bool) {
	v := ctx.Value(apiKeyCtxKey{})
	if v == nil {
		return nil, false
	}
	k, ok := v.(*APIKey)
	return k, ok && k != nil
}
