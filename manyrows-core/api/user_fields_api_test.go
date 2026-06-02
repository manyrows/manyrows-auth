package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"manyrows-core/core"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// setupUserFieldsRouter creates a router for user-field endpoint tests.
func setupUserFieldsRouter(t *testing.T) *chi.Mux {
	t.Helper()
	svc := NewTestServices(t)
	r, wsRouter := NewAdminWorkspaceRouter(t, svc)

	wsRouter.Get("/userPools/{poolId}/userFields", svc.Handler.HandleGetUserFields)
	wsRouter.Post("/userPools/{poolId}/userFields", svc.Handler.HandleCreateUserField)
	wsRouter.Get("/userPools/{poolId}/userFields/values", svc.Handler.HandleGetUserFieldValues)
	wsRouter.Put("/userPools/{poolId}/userFields/{userFieldId}/users/{userId}", svc.Handler.HandleUpsertUserFieldValue)
	wsRouter.Delete("/userPools/{poolId}/userFields/{userFieldId}/users/{userId}", svc.Handler.HandleDeleteUserFieldValue)

	return r
}

// createUserFieldViaAPI creates a user field via the API and returns the field ID.
func createUserFieldViaAPI(t *testing.T, router *chi.Mux, wsID, poolID string, claims core.TokenClaims, key, label, valueType string) string {
	t.Helper()

	body := map[string]any{
		"key":       key,
		"label":     label,
		"valueType": valueType,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/admin/workspace/"+wsID+"/userPools/"+poolID+"/userFields", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("failed to create user field: status %d, body %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(rr.Body.Bytes(), &resp)
	uf := resp["userField"].(map[string]any)
	return uf["id"].(string)
}

// TestUpsertUserFieldValue_BoolForStringField tests that a boolean value is rejected for a string field.
func TestUpsertUserFieldValue_BoolForStringField(t *testing.T) {
	router := setupUserFieldsRouter(t)
	ctx := context.Background()

	email := "uf-boolstr-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	// Create app+user so we have a userId
	app := testEnv.CreateTestApp(t, ws, acc)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", app.ProjectID)
	}()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "ufuser-"+GenerateUniqueSlug("test")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Create a string field in *this* project
	fieldID := createUserFieldViaAPI(t, router, ws.ID.String(), app.UserPoolID.String(), claims, "str_field", "String Field", "string")
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM user_field_values WHERE user_field_id = $1", fieldID)
		_, _ = pool.Exec(ctx, "DELETE FROM user_fields WHERE id = $1", fieldID)
	}()

	// Try to upsert a boolean value for a string field
	body := map[string]any{"value": true}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/userPools/"+app.UserPoolID.String()+"/userFields/"+fieldID+"/users/"+user.ID.String(), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d for bool value on string field, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestUpsertUserFieldValue_NumberForBoolField tests that a number value is rejected for a bool field.
func TestUpsertUserFieldValue_NumberForBoolField(t *testing.T) {
	router := setupUserFieldsRouter(t)
	ctx := context.Background()

	email := "uf-numbool-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	app := testEnv.CreateTestApp(t, ws, acc)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", app.ProjectID)
	}()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "ufuser-"+GenerateUniqueSlug("test")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Create a bool field
	fieldID := createUserFieldViaAPI(t, router, ws.ID.String(), app.UserPoolID.String(), claims, "bool_field", "Bool Field", "bool")
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM user_field_values WHERE user_field_id = $1", fieldID)
		_, _ = pool.Exec(ctx, "DELETE FROM user_fields WHERE id = $1", fieldID)
	}()

	// Try to upsert a number for a bool field
	body := map[string]any{"value": 42}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/userPools/"+app.UserPoolID.String()+"/userFields/"+fieldID+"/users/"+user.ID.String(), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d for number value on bool field, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestUpsertUserFieldValue_InvalidDate tests that an invalid date value is rejected for a date field.
func TestUpsertUserFieldValue_InvalidDate(t *testing.T) {
	router := setupUserFieldsRouter(t)
	ctx := context.Background()

	email := "uf-baddate-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	app := testEnv.CreateTestApp(t, ws, acc)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", app.ProjectID)
	}()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "ufuser-"+GenerateUniqueSlug("test")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Create a date field
	fieldID := createUserFieldViaAPI(t, router, ws.ID.String(), app.UserPoolID.String(), claims, "date_field", "Date Field", "date")
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM user_field_values WHERE user_field_id = $1", fieldID)
		_, _ = pool.Exec(ctx, "DELETE FROM user_fields WHERE id = $1", fieldID)
	}()

	// Try to upsert an invalid date
	body := map[string]any{"value": "not-a-date"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/userPools/"+app.UserPoolID.String()+"/userFields/"+fieldID+"/users/"+user.ID.String(), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d for invalid date value, got %d: %s", http.StatusBadRequest, rr.Code, rr.Body.String())
	}
}

// TestUpsertUserFieldValue_ValidString tests that a valid string value is accepted for a string field.
func TestUpsertUserFieldValue_ValidString(t *testing.T) {
	router := setupUserFieldsRouter(t)
	ctx := context.Background()

	email := "uf-validstr-" + GenerateUniqueSlug("test") + "@example.com"
	acc := testEnv.CreateTestAccount(t, email)
	ws := testEnv.CreateTestWorkspace(t, acc, "Test WS", GenerateUniqueSlug("ws"))
	project := testEnv.CreateTestProject(t, ws, acc, "Test Project", GenerateUniqueSlug("proj"))
	sess, claims := testEnv.CreateTestSession(t, acc)

	fixtures := &TestFixtures{Account: acc, Workspace: ws, Projects: []core.Project{*project}, Session: sess}
	defer testEnv.CleanupTestData(t, fixtures)

	app := testEnv.CreateTestApp(t, ws, acc)
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM apps WHERE id = $1", app.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", app.ProjectID)
	}()

	user, _, err := testEnv.GetOrCreateUserWithMembership(ctx, "ufuser-"+GenerateUniqueSlug("test")+"@example.com", app, core.UserSourceInvited)
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM users WHERE id = $1", user.ID)
	}()

	// Create a string field
	fieldID := createUserFieldViaAPI(t, router, ws.ID.String(), app.UserPoolID.String(), claims, "valid_str", "Valid String", "string")
	defer func() {
		pool := testEnv.DB.Pool()
		_, _ = pool.Exec(ctx, "DELETE FROM user_field_values WHERE user_field_id = $1", fieldID)
		_, _ = pool.Exec(ctx, "DELETE FROM user_fields WHERE id = $1", fieldID)
	}()

	// Upsert a valid string value
	body := map[string]any{"value": "hello world"}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPut, "/admin/workspace/"+ws.ID.String()+"/userPools/"+app.UserPoolID.String()+"/userFields/"+fieldID+"/users/"+user.ID.String(), bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	testEnv.SetSessionCookie(t, req, claims)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d for valid string value, got %d: %s", http.StatusOK, rr.Code, rr.Body.String())
		return
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	val := resp["value"].(map[string]any)
	if val["id"] == nil || val["id"] == "" {
		t.Errorf("expected value to have an id")
	}
}
