package api_test

// Hard-cap regression tests for products + apps per workspace. The
// caps replaced plan-based limits — they're trivially small (100) so
// the test seeds the cap with a bulk INSERT and only exercises the
// route on the 101st create. Plus a unit test for the new
// CountAppsByWorkspaceID repo helper.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"manyrows-core/core"
	"manyrows-core/utils"
)

// seedProductsBulk inserts n products directly, bypassing the handler
// (which is the path under test).
func seedProductsBulk(t *testing.T, ws *core.Workspace, acc *core.Account, n int) {
	t.Helper()
	ctx := context.Background()
	pool := testEnv.DB.Pool()
	for i := 0; i < n; i++ {
		_, err := pool.Exec(ctx, `
			INSERT INTO products (id, workspace_id, name, created_at, updated_at, created_by_account_id)
			VALUES ($1, $2, $3, now(), now(), $4)
		`, utils.NewUUID(), ws.ID, "seed-project", acc.ID)
		if err != nil {
			t.Fatalf("seed project %d: %v", i, err)
		}
	}
}

// seedAppsBulk inserts n apps in the workspace. Post-(product,type)
// unique-constraint each product can only carry one dev/staging/prod
// app, so to put N apps into one workspace we mint N products + one
// app each. acc owns the products (FK on created_by_account_id).
func seedAppsBulk(t *testing.T, ws *core.Workspace, acc *core.Account, n int) {
	t.Helper()
	ctx := context.Background()
	pool := testEnv.DB.Pool()
	for i := 0; i < n; i++ {
		productID := utils.NewUUID()
		if _, err := pool.Exec(ctx, `
			INSERT INTO products (id, workspace_id, name, created_at, updated_at, created_by_account_id)
			VALUES ($1, $2, $3, now(), now(), $4)
		`, productID, ws.ID, "seed-product-"+GenerateUniqueSlug("p"), acc.ID); err != nil {
			t.Fatalf("seed product %d: %v", i, err)
		}
		userPool, err := testEnv.Repo.CreateUserPool(ctx, ws.ID, "Pool "+GenerateUniqueSlug("p"))
		if err != nil {
			t.Fatalf("seed user pool %d: %v", i, err)
		}
		_, err = pool.Exec(ctx, `
			INSERT INTO apps (id, workspace_id, product_id, user_pool_id, type, enabled, created_at, updated_at)
			VALUES ($1, $2, $3, $4, 'dev', true, now(), now())
		`, utils.NewUUID(), ws.ID, productID, userPool.ID)
		if err != nil {
			t.Fatalf("seed app %d: %v", i, err)
		}
	}
}

// =====================
// Product cap (100/workspace)
// =====================

func TestCreateProduct_HardCap(t *testing.T) {
	router := setupProductsTestRouter(t)

	acc := testEnv.CreateTestAccount(t, "projcap-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	// Seed exactly 100 products so the next create lands at the cap.
	seedProductsBulk(t, ws, acc, 100)

	body, _ := json.Marshal(map[string]any{"name": "one too many"})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/products", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 limitReached, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCreateProduct_AtNinetyNine_StillSucceeds(t *testing.T) {
	// Boundary: 99 existing + 1 create = 100, which is still inside
	// the cap. Catches an off-by-one in the >= comparison.
	router := setupProductsTestRouter(t)

	acc := testEnv.CreateTestAccount(t, "projcap99-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Session: sess})

	seedProductsBulk(t, ws, acc, 99)

	body, _ := json.Marshal(map[string]any{"name": "boundary project"})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/products", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =====================
// App cap (100/workspace, summed across products)
// =====================

func TestCreateApp_HardCap(t *testing.T) {
	router := setupAppsRouter(t)

	acc := testEnv.CreateTestAccount(t, "appcap-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProduct(t, ws, acc, "Test Product", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*project}, Session: sess})

	// 100 apps across the project saturates the workspace cap.
	seedAppsBulk(t, ws, acc, 100)

	body, _ := json.Marshal(map[string]any{"name": "one too many", "type": "dev"})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/products/"+project.ID.String()+"/apps", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409 limitReached, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestCreateApp_HardCap_SumsAcrossProducts(t *testing.T) {
	// The cap is per-workspace, NOT per-project — 50 apps in project A
	// plus 50 in project B should still hit the workspace cap when
	// project A tries to create its 51st.
	router := setupAppsRouter(t)

	acc := testEnv.CreateTestAccount(t, "appcap2-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	projA := testEnv.CreateTestProduct(t, ws, acc, "Product A", GenerateUniqueSlug("a"))
	projB := testEnv.CreateTestProduct(t, ws, acc, "Product B", GenerateUniqueSlug("b"))
	sess, claims := testEnv.CreateTestSession(t, acc)
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*projA, *projB}, Session: sess})

	seedAppsBulk(t, ws, acc, 50)
	seedAppsBulk(t, ws, acc, 50)

	body, _ := json.Marshal(map[string]any{"name": "across-products", "type": "dev"})
	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+ws.ID.String()+"/products/"+projA.ID.String()+"/apps", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("expected 409 across-products, got %d: %s", rr.Code, rr.Body.String())
	}
}

// =====================
// CountAppsByWorkspaceID
// =====================

func TestCountAppsByWorkspaceID(t *testing.T) {
	acc := testEnv.CreateTestAccount(t, "countapps-"+GenerateUniqueSlug("test")+"@example.com")
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	projA := testEnv.CreateTestProduct(t, ws, acc, "Product A", GenerateUniqueSlug("a"))
	projB := testEnv.CreateTestProduct(t, ws, acc, "Product B", GenerateUniqueSlug("b"))
	defer testEnv.CleanupTestData(t, &TestFixtures{Account: acc, Workspace: ws, Products: []core.Product{*projA, *projB}})

	ctx := context.Background()
	if got, err := testEnv.Repo.CountAppsByWorkspaceID(ctx, ws.ID); err != nil || got != 0 {
		t.Errorf("empty workspace: got (%d, %v), want (0, nil)", got, err)
	}

	seedAppsBulk(t, ws, acc, 3)
	seedAppsBulk(t, ws, acc, 7)

	if got, err := testEnv.Repo.CountAppsByWorkspaceID(ctx, ws.ID); err != nil || got != 10 {
		t.Errorf("after seed: got (%d, %v), want (10, nil)", got, err)
	}
}
