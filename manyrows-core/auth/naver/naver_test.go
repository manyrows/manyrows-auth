package naver

// White-box tests: the package keeps its endpoints in package vars so the
// harness swaps them to an httptest server. These tests must NOT run in
// parallel (they mutate the package-level endpoint vars).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// mockNaver is an httptest-backed stand-in: a token endpoint and the nested
// userinfo endpoint.
type mockNaver struct {
	server      *httptest.Server
	accessToken string
	tokenError  string         // when set, /token returns this OAuth error
	userinfo    map[string]any // returned from /v1/nid/me
}

func newMockNaver(t *testing.T) *mockNaver {
	t.Helper()
	m := &mockNaver{accessToken: "naver-access-abc"}

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2.0/token", func(w http.ResponseWriter, _ *http.Request) {
		if m.tokenError != "" {
			writeJSON(w, map[string]any{"error": m.tokenError, "error_description": "nope"})
			return
		}
		writeJSON(w, map[string]any{"access_token": m.accessToken, "token_type": "bearer"})
	})
	mux.HandleFunc("/v1/nid/me", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, m.userinfo)
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)

	prevTok, prevUI := tokenURL, userinfoURL
	tokenURL = m.server.URL + "/oauth2.0/token"
	userinfoURL = m.server.URL + "/v1/nid/me"
	t.Cleanup(func() { tokenURL, userinfoURL = prevTok, prevUI })
	return m
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func naverUserinfo(id, email, name string) map[string]any {
	return map[string]any{
		"resultcode": "00",
		"message":    "success",
		"response":   map[string]any{"id": id, "email": email, "name": name},
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	got := BuildAuthorizeURL("client-1", "https://app.example.com/cb", "state-xyz")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Host != "nid.naver.com" || u.Path != "/oauth2.0/authorize" {
		t.Errorf("unexpected base: %s", got)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code",
		"client_id":     "client-1",
		"redirect_uri":  "https://app.example.com/cb",
		"state":         "state-xyz",
	} {
		if g := q.Get(k); g != want {
			t.Errorf("query %s: got %q, want %q", k, g, want)
		}
	}
}

func TestExchangeAuthCode_HappyPath(t *testing.T) {
	m := newMockNaver(t)
	m.userinfo = naverUserinfo("32742776", "User@Naver.com", "홍길동")

	info, err := ExchangeAuthCode(context.Background(), "code", "state", "client-1", "secret")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if info.Sub != "32742776" {
		t.Errorf("sub = %q", info.Sub)
	}
	if info.Email != "user@naver.com" { // normalized to lower-case
		t.Errorf("email = %q, want lowercased", info.Email)
	}
	if info.Name != "홍길동" {
		t.Errorf("name = %q", info.Name)
	}
}

// The user didn't consent to share email → empty email, but a valid subject.
// The workspace handler turns the empty email into emailNotProvided.
func TestExchangeAuthCode_NoEmail(t *testing.T) {
	m := newMockNaver(t)
	m.userinfo = naverUserinfo("321", "", "name")

	info, err := ExchangeAuthCode(context.Background(), "code", "state", "client-1", "secret")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if info.Email != "" {
		t.Errorf("email should be empty, got %q", info.Email)
	}
	if info.Sub != "321" {
		t.Errorf("sub = %q", info.Sub)
	}
}

func TestExchangeAuthCode_TokenError(t *testing.T) {
	m := newMockNaver(t)
	m.tokenError = "invalid_grant"
	if _, err := ExchangeAuthCode(context.Background(), "code", "state", "client-1", "secret"); err == nil {
		t.Fatal("expected token-error rejection")
	}
}

// Naver signals userinfo failures with a non-"00" resultcode and HTTP 200.
func TestExchangeAuthCode_UserinfoResultError(t *testing.T) {
	m := newMockNaver(t)
	m.userinfo = map[string]any{"resultcode": "024", "message": "Authentication failed"}
	if _, err := ExchangeAuthCode(context.Background(), "code", "state", "client-1", "secret"); err == nil {
		t.Fatal("expected userinfo resultcode rejection")
	}
}

// A missing subject id is rejected even on an otherwise-OK response.
func TestExchangeAuthCode_NoSubject(t *testing.T) {
	m := newMockNaver(t)
	m.userinfo = naverUserinfo("", "user@naver.com", "name")
	if _, err := ExchangeAuthCode(context.Background(), "code", "state", "client-1", "secret"); err == nil {
		t.Fatal("expected missing-subject rejection")
	}
}
