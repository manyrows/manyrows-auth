package api

import (
	"context"
	"testing"
	"time"

	"manyrows-core/core"
	"manyrows-core/crypto/passwordhash"

	"github.com/gofrs/uuid/v5"
)

// bfpMockPWRepo satisfies the unexported passwordAuthRepo interface so we can
// drive validateAppPasswordCredentials without a database.
type bfpMockPWRepo struct {
	user *core.User
	hash string
}

func (m *bfpMockPWRepo) GetUserWithPasswordByEmailAndApp(ctx context.Context, email string, app *core.App) (*core.User, string, error) {
	return m.user, m.hash, nil
}

func bfpLockedVerifiedUser(t *testing.T, password string) (*core.User, string) {
	t.Helper()
	hash, err := passwordhash.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	now := time.Now().UTC()
	future := now.Add(15 * time.Minute)
	u := &core.User{
		ID:              uuid.Must(uuid.NewV4()),
		Email:           "locked@example.com",
		EmailVerifiedAt: &now,
		LockedUntil:     &future,
	}
	return u, hash
}

func TestValidatePassword_LockoutEnforcedWhenProtectionOn(t *testing.T) {
	user, hash := bfpLockedVerifiedUser(t, "correcthorse123")
	repo := &bfpMockPWRepo{user: user, hash: hash}
	app := &core.App{BruteForceProtectionEnabled: true}

	res, err := validateAppPasswordCredentials(context.Background(), repo, app, user.Email, "correcthorse123")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if res.Outcome != PWAuthLocked {
		t.Fatalf("protection on: expected PWAuthLocked, got %v", res.Outcome)
	}
}

func TestValidatePassword_LockoutBypassedWhenProtectionOff(t *testing.T) {
	user, hash := bfpLockedVerifiedUser(t, "correcthorse123")
	repo := &bfpMockPWRepo{user: user, hash: hash}
	app := &core.App{BruteForceProtectionEnabled: false}

	// Same locked user + correct password: with protection off the lockout
	// window is ignored, so the verify proceeds and succeeds.
	res, err := validateAppPasswordCredentials(context.Background(), repo, app, user.Email, "correcthorse123")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if res.Outcome != PWAuthOK {
		t.Fatalf("protection off: expected PWAuthOK (lockout bypassed), got %v", res.Outcome)
	}
}
