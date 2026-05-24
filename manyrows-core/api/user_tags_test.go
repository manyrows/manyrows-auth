package api_test

// Tests for the user_tags repo + handlers. Same admin/workspace router
// scaffold as the insights tests; live Postgres via testEnv.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"

	"github.com/go-chi/chi/v5"
	"github.com/gofrs/uuid/v5"
)

func setupTagsRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)

	wsRouter.Route("/products/{productId}/apps/{appId}", func(r chi.Router) {
		r.Get("/users/{userId}/tags", svc.Handler.HandleListUserTags)
		r.Put("/users/{userId}/tags", svc.Handler.HandleReplaceUserTags)
		r.Get("/tags", svc.Handler.HandleListAppTags)
	})

	return r
}

type tagsFixture struct {
	router *chi.Mux
	acc    *core.Account
	ws     *core.Workspace
	app    *core.App
	claims core.TokenClaims
}

func newTagsFixture(t *testing.T) *tagsFixture {
	t.Helper()
	router := setupTagsRouter(t)

	emailAddr := "tags-" + GenerateUniqueSlug("t") + "@example.com"
	acc := testEnv.CreateTestAccount(t, emailAddr)
	ws := testEnv.CreateTestWorkspace(t, acc, "Tags WS", GenerateUniqueSlug("ws"))
	app := testEnv.CreateTestApp(t, ws, acc)
	_, claims := testEnv.CreateTestSession(t, acc)

	t.Cleanup(func() {
		ctx := context.Background()
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM user_tags WHERE app_id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM products WHERE id = $1", app.ProductID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspace_admins WHERE workspace_id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM workspaces WHERE id = $1", ws.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM accounts WHERE id = $1", acc.ID)
	})

	return &tagsFixture{router: router, acc: acc, ws: ws, app: app, claims: claims}
}

func hitTags(t *testing.T, fix *tagsFixture, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	url := fmt.Sprintf("/admin/workspace/%s/products/%s/apps/%s%s",
		fix.ws.ID, fix.app.ProductID, fix.app.ID, path)
	var buf *bytesReader
	if body != nil {
		b, _ := json.Marshal(body)
		buf = newBytesReader(b)
	}
	var req *http.Request
	if buf != nil {
		req = httptest.NewRequest(method, url, buf)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, url, nil)
	}
	testEnv.SetSessionCookie(t, req, fix.claims)
	rr := httptest.NewRecorder()
	fix.router.ServeHTTP(rr, req)
	return rr
}

// Tiny bytes reader so we don't have to import bytes in every test file.
type bytesReader struct {
	b   []byte
	pos int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{b: b} }
func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

/* -------------------------------------------------------------------------- */
/* repo-level tests (normalization + persistence + cross-app isolation)        */
/* -------------------------------------------------------------------------- */

func TestUserTags_ReplaceNormalizes(t *testing.T) {
	fix := newTagsFixture(t)
	user := insertTestUser(t, "registered", fix.app.ID)

	resp := hitTags(t, fix, http.MethodPut, "/users/"+user.String()+"/tags",
		map[string]any{"tags": []string{
			"  VIP  ",  // trim + lowercase
			"vip",      // dup of above after normalize
			"INTERNAL", // lowercase
			"",         // empty → drop
			"   ",      // whitespace → drop
			"this-tag-is-way-too-long-and-exceeds-the-forty-character-limit", // > 40
		}},
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("status %d: %s", resp.Code, resp.Body.String())
	}

	var got map[string][]string
	_ = json.Unmarshal(resp.Body.Bytes(), &got)
	tags := got["tags"]

	want := map[string]bool{"vip": true, "internal": true}
	if len(tags) != len(want) {
		t.Errorf("got %d tags after normalize, want %d (%v)", len(tags), len(want), tags)
	}
	for _, tag := range tags {
		if !want[tag] {
			t.Errorf("unexpected tag %q in normalized output %v", tag, tags)
		}
	}
}

func TestUserTags_ReplaceIsAtomic(t *testing.T) {
	// PUT replaces — old tags should be gone, only new set remains.
	fix := newTagsFixture(t)
	user := insertTestUser(t, "registered", fix.app.ID)

	hitTags(t, fix, http.MethodPut, "/users/"+user.String()+"/tags",
		map[string]any{"tags": []string{"a", "b", "c"}})
	hitTags(t, fix, http.MethodPut, "/users/"+user.String()+"/tags",
		map[string]any{"tags": []string{"x"}})

	rr := hitTags(t, fix, http.MethodGet, "/users/"+user.String()+"/tags", nil)
	var got map[string][]string
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if len(got["tags"]) != 1 || got["tags"][0] != "x" {
		t.Errorf("after replace, tags = %v, want [x]", got["tags"])
	}
}

func TestUserTags_EmptyArrayWipes(t *testing.T) {
	// PUT with [] is the documented "remove all tags" path.
	fix := newTagsFixture(t)
	user := insertTestUser(t, "registered", fix.app.ID)

	hitTags(t, fix, http.MethodPut, "/users/"+user.String()+"/tags",
		map[string]any{"tags": []string{"keep", "me"}})

	hitTags(t, fix, http.MethodPut, "/users/"+user.String()+"/tags",
		map[string]any{"tags": []string{}})

	rr := hitTags(t, fix, http.MethodGet, "/users/"+user.String()+"/tags", nil)
	var got map[string][]string
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if len(got["tags"]) != 0 {
		t.Errorf("expected empty tags after wipe, got %v", got["tags"])
	}
}

func TestUserTags_DistinctAcrossApp(t *testing.T) {
	fix := newTagsFixture(t)
	userA := insertTestUser(t, "registered", fix.app.ID)
	userB := insertTestUser(t, "registered", fix.app.ID)

	hitTags(t, fix, http.MethodPut, "/users/"+userA.String()+"/tags",
		map[string]any{"tags": []string{"vip", "internal"}})
	hitTags(t, fix, http.MethodPut, "/users/"+userB.String()+"/tags",
		map[string]any{"tags": []string{"vip", "beta"}})

	rr := hitTags(t, fix, http.MethodGet, "/tags", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var got map[string][]string
	_ = json.Unmarshal(rr.Body.Bytes(), &got)

	want := map[string]bool{"vip": true, "internal": true, "beta": true}
	if len(got["tags"]) != len(want) {
		t.Errorf("distinct tags = %v, want 3 (vip / internal / beta)", got["tags"])
	}
	for _, tag := range got["tags"] {
		if !want[tag] {
			t.Errorf("unexpected distinct tag %q", tag)
		}
	}
}

func TestUserTags_PerUserIsolation(t *testing.T) {
	fix := newTagsFixture(t)
	userA := insertTestUser(t, "registered", fix.app.ID)
	userB := insertTestUser(t, "registered", fix.app.ID)

	hitTags(t, fix, http.MethodPut, "/users/"+userA.String()+"/tags",
		map[string]any{"tags": []string{"alpha"}})

	rr := hitTags(t, fix, http.MethodGet, "/users/"+userB.String()+"/tags", nil)
	var got map[string][]string
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if len(got["tags"]) != 0 {
		t.Errorf("userB should have no tags; got %v", got["tags"])
	}
}

func TestUserTags_Caps50PerUser(t *testing.T) {
	fix := newTagsFixture(t)
	user := insertTestUser(t, "registered", fix.app.ID)

	tags := make([]string, 200)
	for i := range tags {
		tags[i] = fmt.Sprintf("tag-%03d", i)
	}
	rr := hitTags(t, fix, http.MethodPut, "/users/"+user.String()+"/tags",
		map[string]any{"tags": tags})
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}

	var got map[string][]string
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if len(got["tags"]) > 50 {
		t.Errorf("got %d tags, want <= 50 (server-side cap)", len(got["tags"]))
	}
}

/* -------------------------------------------------------------------------- */
/* batch fetch (used by HandleGetProductMembers)                               */
/* -------------------------------------------------------------------------- */

func TestUserTags_BatchFetchByUserIDs(t *testing.T) {
	fix := newTagsFixture(t)
	userA := insertTestUser(t, "registered", fix.app.ID)
	userB := insertTestUser(t, "registered", fix.app.ID)
	userC := insertTestUser(t, "registered", fix.app.ID) // no tags

	hitTags(t, fix, http.MethodPut, "/users/"+userA.String()+"/tags",
		map[string]any{"tags": []string{"alpha", "beta"}})
	hitTags(t, fix, http.MethodPut, "/users/"+userB.String()+"/tags",
		map[string]any{"tags": []string{"gamma"}})

	got, err := testEnv.Repo.GetUserTagsForUsers(context.Background(), fix.app.ID,
		[]uuid.UUID{userA, userB, userC},
	)
	if err != nil {
		t.Fatalf("GetUserTagsForUsers: %v", err)
	}
	if len(got[userA]) != 2 {
		t.Errorf("userA tags = %v, want 2", got[userA])
	}
	if len(got[userB]) != 1 {
		t.Errorf("userB tags = %v, want 1", got[userB])
	}
	if _, ok := got[userC]; ok {
		t.Errorf("userC has no tags but appears in map: %v", got[userC])
	}
}
