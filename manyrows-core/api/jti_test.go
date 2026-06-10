package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/gofrs/uuid/v5"
)

// doFullGrantTokens runs the full OIDC authorize → code → token exchange and
// returns both the access_token and id_token strings. It calls enableOIDC and
// seedSessionForApp on the provided env, so the env must be freshly created.
func doFullGrantTokens(t *testing.T, e *oidcTestEnv) (accessToken, idToken string) {
	t.Helper()
	redirect := "https://customer.example/callback"
	e.enableOIDC(t, []string{redirect}, nil, "")
	_, accessJWT := e.seedSessionForApp(t)
	verifier, challenge := makePKCE()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {e.app.ID.String()},
		"redirect_uri":          {redirect},
		"scope":                 {"openid email offline_access"},
		"state":                 {"s"},
		"nonce":                 {"n"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	rr := authorizeGET(e, q, accessJWT)
	loc, _ := url.Parse(rr.Header().Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code from authorize (rr=%d %s)", rr.Code, rr.Body.String())
	}

	tok := oidcPostForm(e, "/oidc/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"client_id":     {e.app.ID.String()},
	})
	if tok.Code != http.StatusOK {
		t.Fatalf("token exchange: %d %s", tok.Code, tok.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(tok.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal token response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("no access_token in response: %s", tok.Body.String())
	}
	if resp.IDToken == "" {
		t.Fatalf("no id_token in response: %s", tok.Body.String())
	}
	return resp.AccessToken, resp.IDToken
}

// TestTokens_CarryUniqueJTI verifies that:
//   - Every issued access token and id token carries a non-empty "jti" claim
//     that parses as a valid UUID.
//   - Two access tokens issued in separate grants have distinct jtis.
//   - Two id tokens issued in separate grants have distinct jtis.
//   - Within a single grant the access-token jti differs from the id-token jti.
func TestTokens_CarryUniqueJTI(t *testing.T) {
	e1 := setupOIDCRouter(t)
	at1, idt1 := doFullGrantTokens(t, e1)

	e2 := setupOIDCRouter(t)
	at2, idt2 := doFullGrantTokens(t, e2)

	checkJTI := func(label, tok string) string {
		t.Helper()
		payload := decodeJWTPayload(t, tok)
		raw, ok := payload["jti"]
		if !ok {
			t.Errorf("%s: missing jti claim", label)
			return ""
		}
		s, _ := raw.(string)
		if s == "" {
			t.Errorf("%s: jti claim is empty", label)
			return ""
		}
		if _, err := uuid.FromString(s); err != nil {
			t.Errorf("%s: jti %q does not parse as UUID: %v", label, s, err)
		}
		return s
	}

	jtiAT1 := checkJTI("grant1 access_token", at1)
	jtiIDT1 := checkJTI("grant1 id_token", idt1)
	jtiAT2 := checkJTI("grant2 access_token", at2)
	jtiIDT2 := checkJTI("grant2 id_token", idt2)

	if jtiAT1 != "" && jtiAT2 != "" && jtiAT1 == jtiAT2 {
		t.Errorf("access token jtis are identical across grants: %s", jtiAT1)
	}
	if jtiIDT1 != "" && jtiIDT2 != "" && jtiIDT1 == jtiIDT2 {
		t.Errorf("id token jtis are identical across grants: %s", jtiIDT1)
	}
	if jtiAT1 != "" && jtiIDT1 != "" && jtiAT1 == jtiIDT1 {
		t.Errorf("grant1: access_token jti == id_token jti (%s), must differ", jtiAT1)
	}
}
