package api_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"manyrows-core/utils"
)

// seedAuthLog inserts a raw auth_logs row so the test controls every PII column.
func seedAuthLog(t *testing.T, wsID, appID, subjectUserID interface{}, email, ip, ua string) {
	t.Helper()
	seedAuthLogFull(t, wsID, appID, subjectUserID, email, ip, ua, "login.password", nil)
}

// seedAuthLogFull is seedAuthLog with an explicit event and optional metadata
// (passed as a JSON string, or "" for SQL NULL).
func seedAuthLogFull(t *testing.T, wsID, appID, subjectUserID interface{}, email, ip, ua, event, metadata interface{}) {
	t.Helper()
	ctx := context.Background()
	_, err := testEnv.DB.Pool().Exec(ctx, `
		INSERT INTO auth_logs (id, workspace_id, app_id, event, outcome, actor_type, subject_user_id, email_attempted, actor_label, ip, user_agent, metadata)
		VALUES ($1,$2,$3,$8,'success','self',$4,$5,$5,$6::inet,$7,$9::jsonb)`,
		utils.NewUUID(), wsID, appID, subjectUserID, email, ip, ua, event, metadata)
	if err != nil {
		t.Fatalf("seed auth_log: %v", err)
	}
}

func TestEraseUser_AnonymizesAndDeletes(t *testing.T) {
	ctx := context.Background()
	emailAddr := "erase-" + GenerateUniqueSlug("t") + "@example.com"
	oldEmailAddr := "old-" + GenerateUniqueSlug("t") + "@example.com"
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
	// An email-change event for the subject: metadata records the OLD address.
	changeMeta := fmt.Sprintf(`{"old_email":%q,"new_email":%q}`, oldEmailAddr, emailAddr)
	seedAuthLogFull(t, ws.ID, app.ID, user.ID, emailAddr, "203.0.113.7", "agent-D", "email.changed", changeMeta)
	// A null-subject failed-login row under the OLD address: matchable ONLY via
	// the historical-email path derived from the email.changed metadata above.
	seedAuthLog(t, ws.ID, app.ID, nil, oldEmailAddr, "203.0.113.8", "agent-E")
	// Other user's log — control.
	seedAuthLog(t, ws.ID, app.ID, other.ID, otherEmail, "203.0.113.9", "agent-C")

	// Subject's rate-limit attempts (seeded but no longer asserted on — erasure
	// intentionally does not delete attempts to avoid cross-tenant lockout reset).
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

	// Every auth_log in this workspace except the control row must be fully
	// scrubbed. The control row (other user) must be untouched.
	rows, _ := testEnv.DB.Pool().Query(ctx,
		"SELECT email_attempted, host(ip), user_agent, actor_label, metadata::text FROM auth_logs WHERE workspace_id = $1", ws.ID)
	defer rows.Close()
	var scrubbedRows, otherIntact int
	for rows.Next() {
		var em, ip, ua, al, meta *string
		_ = rows.Scan(&em, &ip, &ua, &al, &meta)
		if em != nil && *em == otherEmail {
			otherIntact++
			continue
		}
		// every non-control row must be fully scrubbed, including metadata
		if em != nil || ip != nil || ua != nil || al != nil || meta != nil {
			t.Fatalf("subject auth_log not fully anonymized: em=%v ip=%v ua=%v al=%v meta=%v", em, ip, ua, al, meta)
		}
		scrubbedRows++
	}
	// 4 subject-related rows were seeded (subject-keyed login, email-keyed login,
	// email.changed, and the historical-email failed-login).
	if scrubbedRows != 4 {
		t.Fatalf("expected 4 anonymized subject rows, got %d", scrubbedRows)
	}
	if otherIntact != 1 {
		t.Fatalf("other user's auth_log was disturbed (intact=%d)", otherIntact)
	}

	// No row under the OLD (historical) address survives with a non-null ip:
	// the historical-email path must have anonymized it.
	_ = testEnv.DB.Pool().QueryRow(ctx,
		"SELECT count(*) FROM auth_logs WHERE workspace_id = $1 AND lower(email_attempted) = lower($2) AND ip IS NOT NULL",
		ws.ID, oldEmailAddr).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("historical-email auth_log row not anonymized (%d rows remain with ip)", cnt)
	}

	// webhook payload scrubbed of email but userId kept.
	var scrubbed string
	_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT payload::text FROM webhook_deliveries WHERE id = $1", deliveryID).Scan(&scrubbed)
	if strings.Contains(scrubbed, emailAddr) {
		t.Fatalf("payload still contains email: %s", scrubbed)
	}
	if !strings.Contains(scrubbed, user.ID.String()) {
		t.Fatalf("payload lost userId: %s", scrubbed)
	}
}

func TestEraseUserIfOrphanInPool(t *testing.T) {
	ctx := context.Background()

	t.Run("orphan is erased", func(t *testing.T) {
		emailAddr := "orphan-" + GenerateUniqueSlug("t") + "@example.com"
		acc := testEnv.CreateTestAccount(t, emailAddr)
		ws := testEnv.CreateTestWorkspace(t, acc, "ORPHAN WS", GenerateUniqueSlug("ws"))
		app := testEnv.CreateTestApp(t, ws, acc)
		user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, "invited")
		if err != nil {
			t.Fatalf("create user: %v", err)
		}

		// Strip the membership so the user is an orphan in the pool.
		if _, err := testEnv.DB.Pool().Exec(ctx, "DELETE FROM app_users WHERE user_id = $1", user.ID); err != nil {
			t.Fatalf("delete membership: %v", err)
		}

		seedAuthLog(t, ws.ID, app.ID, user.ID, emailAddr, "203.0.113.11", "agent-orphan")

		erased, err := testEnv.Repo.EraseUserIfOrphanInPool(ctx, user.ID, app.UserPoolID, emailAddr, ws.ID)
		if err != nil {
			t.Fatalf("EraseUserIfOrphanInPool: %v", err)
		}
		if !erased {
			t.Fatalf("expected orphan to be erased, got erased=false")
		}

		var cnt int
		_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM users WHERE id = $1", user.ID).Scan(&cnt)
		if cnt != 0 {
			t.Fatalf("orphan user row not deleted")
		}

		// auth_log ip nulled.
		_ = testEnv.DB.Pool().QueryRow(ctx,
			"SELECT count(*) FROM auth_logs WHERE workspace_id = $1 AND ip IS NOT NULL", ws.ID).Scan(&cnt)
		if cnt != 0 {
			t.Fatalf("orphan auth_log ip not nulled (%d rows with ip)", cnt)
		}
	})

	t.Run("user with membership is skipped", func(t *testing.T) {
		emailAddr := "keep-" + GenerateUniqueSlug("t") + "@example.com"
		acc := testEnv.CreateTestAccount(t, emailAddr)
		ws := testEnv.CreateTestWorkspace(t, acc, "KEEP WS", GenerateUniqueSlug("ws"))
		app := testEnv.CreateTestApp(t, ws, acc)
		user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, emailAddr, app, "invited")
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		t.Cleanup(func() {
			_, _ = testEnv.DB.Pool().Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
		})

		seedAuthLog(t, ws.ID, app.ID, user.ID, emailAddr, "203.0.113.12", "agent-keep")

		erased, err := testEnv.Repo.EraseUserIfOrphanInPool(ctx, user.ID, app.UserPoolID, emailAddr, ws.ID)
		if err != nil {
			t.Fatalf("EraseUserIfOrphanInPool: %v", err)
		}
		if erased {
			t.Fatalf("expected user with membership to be skipped, got erased=true")
		}

		var cnt int
		_ = testEnv.DB.Pool().QueryRow(ctx, "SELECT count(*) FROM users WHERE id = $1", user.ID).Scan(&cnt)
		if cnt != 1 {
			t.Fatalf("user with membership was deleted (count=%d)", cnt)
		}

		// auth_log ip UNCHANGED (not nulled).
		var ip *string
		_ = testEnv.DB.Pool().QueryRow(ctx,
			"SELECT host(ip) FROM auth_logs WHERE workspace_id = $1", ws.ID).Scan(&ip)
		if ip == nil || *ip != "203.0.113.12" {
			t.Fatalf("auth_log ip was disturbed for skipped user: %v", ip)
		}
	})
}
