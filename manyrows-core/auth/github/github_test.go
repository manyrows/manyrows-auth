package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestBuildAuthorizeURL(t *testing.T) {
	got := BuildAuthorizeURL("Iv1.client123", "https://api.example.com/cb", "state-xyz")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Host != "github.com" || u.Path != "/login/oauth/authorize" {
		t.Errorf("unexpected base: %s", got)
	}
	q := u.Query()
	checks := map[string]string{
		"client_id":    "Iv1.client123",
		"redirect_uri": "https://api.example.com/cb",
		"scope":        "read:user user:email",
		"state":        "state-xyz",
		"allow_signup": "true",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %s: got %q, want %q", k, got, want)
		}
	}
}

func TestBuildAuthorizeURL_StateEscaping(t *testing.T) {
	// State tokens are base64url and won't normally contain `&` or `=`,
	// but BuildAuthorizeURL should still escape them if a future state
	// scheme allows them. Verifies url.Values escaping is in play.
	got := BuildAuthorizeURL("c", "https://x/cb", "abc&def=ghi")
	u, _ := url.Parse(got)
	if u.Query().Get("state") != "abc&def=ghi" {
		t.Errorf("state round-trip failed: %q", u.Query().Get("state"))
	}
}

// fakeGithubAPI returns a test server that mimics the subset of
// GitHub's REST API we exercise: /user and /user/emails.
func fakeGithubAPI(t *testing.T, userBody string, emailsBody string, emailsStatus int) (string, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(emailsStatus)
		_, _ = w.Write([]byte(emailsBody))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(userBody))
	})
	srv := httptest.NewServer(mux)
	return srv.URL, srv.Close
}

// withFakeGithubURLs swaps the package-level constants for tests.
// Defer the returned restore func.
func withFakeGithubURLs(t *testing.T, base string) func() {
	t.Helper()
	origUser, origEmails := userURL, emailsURL
	userURL = base + "/user"
	emailsURL = base + "/user/emails"
	return func() { userURL = origUser; emailsURL = origEmails }
}

func TestFetchPrimaryVerifiedEmail_Lifecycle(t *testing.T) {
	cases := []struct {
		name       string
		emailsBody string
		wantEmail  string
		wantErrIs  error
	}{
		{
			"primary verified — returns it",
			`[{"email":"bob@example.com","primary":true,"verified":true,"visibility":"public"},
			  {"email":"bob+spam@example.com","primary":false,"verified":true}]`,
			"bob@example.com",
			nil,
		},
		{
			"primary unverified, secondary verified — REJECTED (no fallback)",
			`[{"email":"primary@example.com","primary":true,"verified":false},
			  {"email":"secondary@example.com","primary":false,"verified":true}]`,
			"",
			ErrNoVerifiedEmail,
		},
		{
			"all unverified — rejected",
			`[{"email":"a@example.com","primary":true,"verified":false},
			  {"email":"b@example.com","primary":false,"verified":false}]`,
			"",
			ErrNoVerifiedEmail,
		},
		{
			"empty list — rejected",
			`[]`,
			"",
			ErrNoVerifiedEmail,
		},
		{
			"primary with mixed-case + whitespace — normalized",
			`[{"email":"  Bob@Example.com  ","primary":true,"verified":true}]`,
			"bob@example.com",
			nil,
		},
		{
			"only one entry, primary verified",
			`[{"email":"only@example.com","primary":true,"verified":true}]`,
			"only@example.com",
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base, cleanup := fakeGithubAPI(t, `{"id":1,"login":"x"}`, c.emailsBody, http.StatusOK)
			defer cleanup()
			restore := withFakeGithubURLs(t, base)
			defer restore()

			got, err := fetchPrimaryVerifiedEmail(context.Background(), "fake-token")
			if c.wantErrIs != nil {
				if !errors.Is(err, c.wantErrIs) {
					t.Errorf("expected %v, got %v", c.wantErrIs, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.wantEmail {
				t.Errorf("got %q, want %q", got, c.wantEmail)
			}
		})
	}
}

func TestFetchPrimaryVerifiedEmail_BadStatus(t *testing.T) {
	base, cleanup := fakeGithubAPI(t, `{"id":1}`, `nope`, http.StatusUnauthorized)
	defer cleanup()
	restore := withFakeGithubURLs(t, base)
	defer restore()

	_, err := fetchPrimaryVerifiedEmail(context.Background(), "fake-token")
	if err == nil {
		t.Fatal("expected error for non-200 emails response")
	}
	if !errors.Is(err, ErrUserFetch) {
		t.Errorf("expected ErrUserFetch, got %v", err)
	}
}

func TestFetchPrimaryVerifiedEmail_BadJSON(t *testing.T) {
	base, cleanup := fakeGithubAPI(t, `{"id":1}`, `not json`, http.StatusOK)
	defer cleanup()
	restore := withFakeGithubURLs(t, base)
	defer restore()

	_, err := fetchPrimaryVerifiedEmail(context.Background(), "fake-token")
	if err == nil {
		t.Fatal("expected error for malformed emails JSON")
	}
}

// TestFetchUser confirms the /user request is sent with the right
// headers and decodes the numeric ID correctly.
func TestFetchUser(t *testing.T) {
	mux := http.NewServeMux()
	var sawAccept, sawVersion string
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		sawAccept = r.Header.Get("Accept")
		sawVersion = r.Header.Get("X-GitHub-Api-Version")
		_, _ = w.Write([]byte(`{"id":42,"login":"octocat","name":"The Octocat","email":"oct@example.com"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origUser := userURL
	userURL = srv.URL + "/user"
	defer func() { userURL = origUser }()

	u, err := fetchUser(context.Background(), "fake-token")
	if err != nil {
		t.Fatalf("fetchUser: %v", err)
	}
	if u.ID != 42 {
		t.Errorf("id: got %d, want 42", u.ID)
	}
	if u.Login != "octocat" {
		t.Errorf("login: got %q, want octocat", u.Login)
	}
	if sawAccept != "application/vnd.github+json" {
		t.Errorf("Accept header: got %q", sawAccept)
	}
	if sawVersion != "2022-11-28" {
		t.Errorf("X-GitHub-Api-Version header: got %q", sawVersion)
	}
}

// TestExchangeAuthCode_BadCode rejects an empty code without making
// any network calls.
func TestExchangeAuthCode_BadCode(t *testing.T) {
	_, err := ExchangeAuthCode(context.Background(), "  ", "client", "secret", "https://x/cb")
	if !errors.Is(err, ErrCodeExchange) {
		t.Errorf("expected ErrCodeExchange, got %v", err)
	}
}

// Round-trip the full flow against fakes, asserting we end up with
// a TokenInfo containing the GitHub numeric ID stringified and the
// verified primary email.
func TestExchangeAuthCode_FullFlow(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("token endpoint: Accept = %q", r.Header.Get("Accept"))
		}
		_ = r.ParseForm()
		if r.PostFormValue("code") != "the-code" {
			t.Errorf("token endpoint: code = %q", r.PostFormValue("code"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_test","token_type":"bearer","scope":"read:user,user:email"}`))
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"id":99,"login":"alice","name":"Alice","email":"alice@example.com"}`))
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"email":"alice@example.com","primary":true,"verified":true}]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origToken, origUser, origEmails := tokenURL, userURL, emailsURL
	tokenURL = srv.URL + "/login/oauth/access_token"
	userURL = srv.URL + "/user"
	emailsURL = srv.URL + "/user/emails"
	defer func() { tokenURL = origToken; userURL = origUser; emailsURL = origEmails }()

	info, err := ExchangeAuthCode(context.Background(), "the-code", "client", "secret", "https://x/cb")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if info.Sub != "99" {
		t.Errorf("Sub: got %q, want 99", info.Sub)
	}
	if info.Email != "alice@example.com" {
		t.Errorf("Email: got %q", info.Email)
	}
	if info.Login != "alice" {
		t.Errorf("Login: got %q", info.Login)
	}
}

// TestExchangeAuthCode_TokenError surfaces GitHub's JSON-body error
// shape (200 + `error` field) as ErrCodeExchange, not a successful
// path with empty token.
func TestExchangeAuthCode_TokenError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]string{
			"error":             "bad_verification_code",
			"error_description": "The code passed is incorrect or expired.",
		})
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	origToken := tokenURL
	tokenURL = srv.URL + "/login/oauth/access_token"
	defer func() { tokenURL = origToken }()

	_, err := ExchangeAuthCode(context.Background(), "the-code", "client", "secret", "https://x/cb")
	if !errors.Is(err, ErrCodeExchange) {
		t.Errorf("expected ErrCodeExchange, got %v", err)
	}
}
