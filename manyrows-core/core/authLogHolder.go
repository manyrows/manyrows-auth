package core

import (
	"context"

	"github.com/gofrs/uuid/v5"
)

// authLogHolder carries the authenticated subject from an auth handler back
// up to the client-auth access-log middleware (context flows down, so the
// outer middleware reads a pointer it seeded and the handler wrote through).
type authLogHolder struct{ userID string }

type authLogCtxKey struct{}

// WithAuthLogHolder seeds an empty subject holder and returns the augmented
// context plus the holder pointer to read after the handler runs.
func WithAuthLogHolder(ctx context.Context) (context.Context, *authLogHolder) {
	h := &authLogHolder{}
	return context.WithValue(ctx, authLogCtxKey{}, h), h
}

// UserID returns the recorded subject, "" if unset. Nil-safe.
func (h *authLogHolder) UserID() string {
	if h == nil {
		return ""
	}
	return h.userID
}

// SetAuthLogUser records the authenticated subject for the access-log line.
// Nil-safe no-op when no holder was seeded (handler reached outside the
// /auth access-log middleware). Call where auth resolves a user.
func SetAuthLogUser(ctx context.Context, userID uuid.UUID) {
	if h, ok := ctx.Value(authLogCtxKey{}).(*authLogHolder); ok && h != nil {
		h.userID = userID.String()
	}
}
