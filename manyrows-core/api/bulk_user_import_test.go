package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

func setupBulkUserImportRouter(t *testing.T, svc *TestServices) *chi.Mux {
	t.Helper()
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)
	wsRouter.Route("/projects/{projectId}/apps/{appId}", func(r chi.Router) {
		r.Post("/users:import", svc.Handler.HandleAdminBulkUserImport)
	})
	return r
}

type importResp struct {
	DryRun  bool `json:"dryRun"`
	Summary struct {
		Total, Created, Updated, Skipped, Failed int
	} `json:"summary"`
	Rows []struct {
		Row     int    `json:"row"`
		Email   string `json:"email"`
		Outcome string `json:"outcome"`
		UserID  string `json:"userId"`
		Errors  []struct {
			Field, Message string
		} `json:"errors"`
		Warnings []string `json:"warnings"`
	} `json:"rows"`
}

func TestBulkUserImport_BatchValidation(t *testing.T) {
	svc := NewTestServices(t)
	router := setupBulkUserImportRouter(t, svc)

	acc := testEnv.CreateTestAccount(t, "imp-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:import", ws.ID, app.ProjectID, app.ID)

	post := func(t *testing.T, payload map[string]any) (*httptest.ResponseRecorder, importResp) {
		t.Helper()
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		testEnv.SetSessionCookie(t, req, claims)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		var out importResp
		if rr.Code == http.StatusOK {
			_ = json.Unmarshal(rr.Body.Bytes(), &out)
		}
		return rr, out
	}

	// Empty rows -> 200 with zeroed summary.
	rr, out := post(t, map[string]any{"rows": []any{}})
	if rr.Code != http.StatusOK {
		t.Fatalf("empty: expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if out.Summary.Total != 0 || out.Summary.Created != 0 {
		t.Fatalf("empty: expected zero summary, got %+v", out.Summary)
	}

	// Bad onConflict -> 400.
	rr, _ = post(t, map[string]any{"onConflict": "merge", "rows": []any{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad onConflict: expected 400, got %d", rr.Code)
	}

	// Over the row cap -> 400.
	tooMany := make([]map[string]any, 1001)
	for i := range tooMany {
		tooMany[i] = map[string]any{"email": fmt.Sprintf("x%d@example.com", i)}
	}
	rr, _ = post(t, map[string]any{"rows": tooMany})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("over cap: expected 400, got %d", rr.Code)
	}

	// Unknown default role -> 400.
	rr, _ = post(t, map[string]any{"defaultRoles": []string{"does-not-exist"}, "rows": []any{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown default role: expected 400, got %d", rr.Code)
	}
}

func TestBulkUserImport_AppNotFound(t *testing.T) {
	svc := NewTestServices(t)
	router := setupBulkUserImportRouter(t, svc)

	acc := testEnv.CreateTestAccount(t, "imp2-"+GenerateUniqueSlug("u")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	// Real project, random app id -> 404.
	url := fmt.Sprintf("/admin/workspace/%s/projects/%s/apps/%s/users:import", ws.ID, app.ProjectID, uuid.Must(uuid.NewV4()).String())
	body, _ := json.Marshal(map[string]any{"rows": []any{}})
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}
