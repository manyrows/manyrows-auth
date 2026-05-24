package microsoft

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestEmailDomainOwnerVerified(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{`true`, true},
		{`"true"`, true},
		{`1`, true},
		{`"1"`, true},
		{`false`, false},
		{`"false"`, false},
		{`0`, false},
		{`"0"`, false},
		{`null`, false},
		{``, false},
		{`"yes"`, false},  // not the truthy-set; reject
		{`"True"`, false}, // case-sensitive on purpose; Microsoft is consistent
	}
	for _, c := range cases {
		got := emailDomainOwnerVerified(json.RawMessage(c.in))
		if got != c.want {
			t.Errorf("emailDomainOwnerVerified(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsMultiTenantConfig(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{TenantCommon, true},
		{TenantOrganizations, true},
		{TenantConsumers, true},
		{"00000000-0000-0000-0000-000000000000", false},
		{"11111111-2222-3333-4444-555555555555", false},
		{"", false}, // not multi-tenant; not anything (rejected upstream)
	}
	for _, c := range cases {
		if got := isMultiTenantConfig(c.in); got != c.want {
			t.Errorf("isMultiTenantConfig(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestIsValidTenant(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"common", true},
		{"organizations", true},
		{"consumers", true},
		{"  common  ", true}, // trim
		{"00000000-0000-0000-0000-000000000000", true},
		{"11111111-2222-3333-4444-555555555555", true},
		{"", false},
		{"random-string", false},
		{"00000000-0000-0000-0000-00000000000z", false},  // bad hex
		{"00000000-0000-0000-0000-0000000000000", false}, // too long
	}
	for _, c := range cases {
		if got := IsValidTenant(c.in); got != c.want {
			t.Errorf("IsValidTenant(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestBuildAuthorizeURL_QueryParams(t *testing.T) {
	got := BuildAuthorizeURL("organizations", "client-abc", "https://api.example.com/cb", "state-xyz")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Host != "login.microsoftonline.com" || !strings.HasSuffix(u.Path, "/oauth2/v2.0/authorize") {
		t.Errorf("unexpected base: %s", got)
	}
	if !strings.Contains(u.Path, "/organizations/") {
		t.Errorf("tenant not in path: %s", u.Path)
	}
	q := u.Query()
	checks := map[string]string{
		"client_id":     "client-abc",
		"redirect_uri":  "https://api.example.com/cb",
		"response_type": "code",
		"response_mode": "query",
		"scope":         "openid email profile",
		"state":         "state-xyz",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %s: got %q, want %q", k, got, want)
		}
	}
}

func TestBuildAuthorizeURL_TenantIsPathEscaped(t *testing.T) {
	// A specific tenant UUID. The host segment must be intact.
	const tenant = "11111111-2222-3333-4444-555555555555"
	got := BuildAuthorizeURL(tenant, "c", "https://x/cb", "s")
	if !strings.Contains(got, "/"+tenant+"/oauth2/v2.0/authorize?") {
		t.Errorf("tenant not in path correctly: %s", got)
	}
}

func TestAllowedForTenant(t *testing.T) {
	cases := []struct {
		token, configured string
		want              bool
	}{
		// Common accepts anything
		{"any-tid", TenantCommon, true},
		{consumersTenantID, TenantCommon, true},

		// Organizations rejects the consumers TID
		{"some-org-tid", TenantOrganizations, true},
		{consumersTenantID, TenantOrganizations, false},

		// Consumers requires the consumers TID exactly
		{consumersTenantID, TenantConsumers, true},
		{"some-org-tid", TenantConsumers, false},

		// Specific tenant: must match (case-insensitive)
		{"00000000-0000-0000-0000-AAAAAAAAAAAA", "00000000-0000-0000-0000-aaaaaaaaaaaa", true},
		{"00000000-0000-0000-0000-aaaaaaaaaaaa", "00000000-0000-0000-0000-bbbbbbbbbbbb", false},
	}
	for _, c := range cases {
		if got := allowedForTenant(c.token, c.configured); got != c.want {
			t.Errorf("allowedForTenant(token=%q, configured=%q): got %v, want %v", c.token, c.configured, got, c.want)
		}
	}
}
