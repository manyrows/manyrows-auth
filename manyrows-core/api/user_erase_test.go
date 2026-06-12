package api_test

import (
	"context"
	"fmt"
	"testing"

	"manyrows-core/utils"
)

// seedAuthLog inserts a raw auth_logs row so the test controls every PII column.
func seedAuthLog(t *testing.T, wsID, appID, subjectUserID interface{}, email, ip, ua string) {
	t.Helper()
	ctx := context.Background()
	_, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, subject_user_id, email_attempted, actor_label, ip, user_agent)
		VALUES ($1,$2,$3,'login.password','success','self',$4,$5,$5,$6::inet,$7)`,
		utils.NewUUID(), wsID, appID, subjectUserID, email, ip, ua)
	if err != nil {
		t.Fatalf("seed auth_log: %v", err)
	}
}

func TestEraseUser_AnonymizesAndDeletes(t *testing.T) {
	ctx := context.Background()
	emailAddr := "erase-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "ERASE WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, "invited")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Another user in the same workspace whose logs must NOT be touched.
	otherEmail := "other-" + GenerateUniqueSlug("t") + "@example.com"
	other, _, err := testEnv.GetOrCreateUserWithMembership(ctx, otherEmail, app, "invited")
	if err != nil {
		t.Fatalf("create other user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", other.ID)
	})

	// Subject's logs: one keyed by subject_user_id, one keyed only by email (no user id).
	seedAuthLog(t, ws.ID, app.ID, user.ID, emailAddr, "203.0.113.5", "agent-A")
	seedAuthLog(t, ws.ID, app.ID, nil, emailAddr, "203.0.113.6", "agent-B")
	// Other user's log — control.
	seedAuthLog(t, ws.ID, app.ID, other.ID, otherEmail, "203.0.113.9", "agent-C")

	// Subject's rate-limit attempts.
	_ = testEnv.Repo.InsertAttempt(ctx, "login_password", emailAddr, "203.0.113.5")

	// A webhook + delivery whose payload carries the subject's email.
	webhookID := utils.NewUUID()
	if _, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO webhooks (id, project_id, app_id, url, secret, events, created_by)
		VALUES ($1,$2,$3,'https://example.com/hook','sek','{}',$4)`,
		webhookID, app.ProjectID, app.ID, acc.ID); err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	deliveryID := utils.NewUUID()
	payload := fmt.Sprintf(`{"userId":%q,"email":%q,"appId":%q}`, user.ID, emailAddr, app.ID)
	if _, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO webhook_deliveries (id, webhook_id, event, payload, status)
		VALUES ($1,$2,'user.login',$3::jsonb,'success')`,
		deliveryID, webhookID, payload); err != nil {
		t.Fatalf("seed delivery: %v", err)
	}

	// Act.
	if err := testEnv.Repo.EraseUser(ctx, user.ID, emailAddr, ws.ID); err != nil {
		t.Fatalf("EraseUser: %v", err)
	}

	// User row gone.
	var cnt int
	_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM users WHERE id = $1", user.ID).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("user row not deleted")
	}

	// Subject's auth_logs anonymized (both rows), but rows preserved.
	rows, _ := testEnv.DB.Pool().Query(ctx,
		"SELECT email_attempted, host(ip), user_agent, actor_label FROM auth_logs WHERE workspace_id = $1", ws.ID)
	defer rows.Close()
	var subjectRows, otherIntact int
	for rows.Next() {
		var em, ip, ua, al *string
		_ = rows.Scan(&em, &ip, &ua, &al)
		if em != nil && *em == otherEmail {
			otherIntact++
			continue
		}
		// every non-other row must be fully scrubbed
		if em != nil || ip != nil || ua != nil || al != nil {
			t.Fatalf("subject auth_log not fully anonymized: em=%v ip=%v ua=%v al=%v", em, ip, ua, al)
		}
		subjectRows++
	}
	if subjectRows != 2 {
		t.Fatalf("expected 2 anonymized subject rows, got %d", subjectRows)
	}
	if otherIntact != 1 {
		t.Fatalf("other user's auth_log was disturbed (intact=%d)", otherIntact)
	}

	// attempts gone.
	_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM attempts WHERE lower(subject) = lower($1)", emailAddr).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("attempts not deleted")
	}

	// webhook payload scrubbed of email but userId kept.
	var scrubbed string
	_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT payload::text FROM webhook_deliveries WHERE id = $1", deliveryID).Scan(&scrubbed)
	if want := emailAddr; containsStr(scrubbed, want) {
		t.Fatalf("payload still contains email: %s", scrubbed)
	}
	if !containsStr(scrubbed, user.ID.String()) {
		t.Fatalf("payload lost userId: %s", scrubbed)
	}
}

func containsStr(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
