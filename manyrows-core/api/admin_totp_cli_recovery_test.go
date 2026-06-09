package api_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"manyrows-core/core"
)

// Repo-level tests for the `reset-admin-2fa <email>` CLI recovery path
// (Repo.DisableAccountTOTPByEmail). The CLI wrapper in start.go is thin glue
// over this method, matching the untested runEncryptionMigration precedent.

func TestDisableAccountTOTPByEmail_ClearsTOTP(t *testing.T) {
	email := "cli-2fa-" + GenerateUniqueSlug("u") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc})
	enableAccountTOTP(t, acc.ID)
	if !accountTOTPEnabled(t, acc.ID) {
		t.Fatal("precondition: account should have TOTP enabled")
	}

	if err := testEnv.Repo.DisableAccountTOTPByEmail(context.Background(), email); err != nil {
		t.Fatalf("DisableAccountTOTPByEmail: %v", err)
	}
	if accountTOTPEnabled(t, acc.ID) {
		t.Error("expected TOTP to be cleared")
	}
}

func TestDisableAccountTOTPByEmail_CaseInsensitive(t *testing.T) {
	email := "cli-2fa-case-" + GenerateUniqueSlug("u") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc})
	enableAccountTOTP(t, acc.ID)

	// Operator may type the email in any case; it must still match.
	if err := testEnv.Repo.DisableAccountTOTPByEmail(context.Background(), strings.ToUpper(email)); err != nil {
		t.Fatalf("uppercase email should match case-insensitively: %v", err)
	}
	if accountTOTPEnabled(t, acc.ID) {
		t.Error("expected TOTP to be cleared via case-insensitive match")
	}
}

func TestDisableAccountTOTPByEmail_NotFound(t *testing.T) {
	err := testEnv.Repo.DisableAccountTOTPByEmail(context.Background(),
		"no-such-"+GenerateUniqueSlug("u")+"@example.com")
	if !errors.Is(err, core.ErrAccountNotFound) {
		t.Fatalf("expected ErrAccountNotFound for an unknown email, got %v", err)
	}
}
