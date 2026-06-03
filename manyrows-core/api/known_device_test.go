package api_test

import (
	"context"
	"testing"

	"manyrows-core/core"
)

// TestUpsertKnownDevice exercises the device-memory upsert that backs
// new-device detection: it must report a device as new exactly once and
// surface how many devices the account already had (so the caller can avoid
// alerting on a user's very first device).
func TestUpsertKnownDevice(t *testing.T) {
	ctx := context.Background()
	acc := testEnv.CreateTestAccount(t, "nd-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws})

	user, _, err := testEnv.Repo.GetOrCreateUser(ctx, "ndu-"+GenerateUniqueSlug("u")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("GetOrCreateUser: %v", err)
	}

	// First device on the account: new, with no prior devices.
	wasNew, prior, err := testEnv.Repo.UpsertKnownDevice(ctx, user.ID, app.ID, "hash-aaa", "UA-A", "1.1.1.1")
	if err != nil {
		t.Fatalf("upsert #1: %v", err)
	}
	if !wasNew || prior != 0 {
		t.Errorf("first device: got wasNew=%v prior=%d, want true/0", wasNew, prior)
	}

	// Same device again: not new; one prior device now exists.
	wasNew, prior, err = testEnv.Repo.UpsertKnownDevice(ctx, user.ID, app.ID, "hash-aaa", "UA-A", "2.2.2.2")
	if err != nil {
		t.Fatalf("upsert #2: %v", err)
	}
	if wasNew || prior != 1 {
		t.Errorf("same device: got wasNew=%v prior=%d, want false/1", wasNew, prior)
	}

	// A genuinely new second device: new, with one prior device.
	wasNew, prior, err = testEnv.Repo.UpsertKnownDevice(ctx, user.ID, app.ID, "hash-bbb", "UA-B", "3.3.3.3")
	if err != nil {
		t.Fatalf("upsert #3: %v", err)
	}
	if !wasNew || prior != 1 {
		t.Errorf("second device: got wasNew=%v prior=%d, want true/1", wasNew, prior)
	}
}
