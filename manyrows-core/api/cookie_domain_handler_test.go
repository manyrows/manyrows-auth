package api

// Pure-function tests for validateCookieDomain. Public-suffix
// rejection is the security-critical bit (cookies on a public suffix
// like github.io scope across unrelated tenants).

import "testing"

func TestValidateCookieDomain(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Accept
		{"empty", "", false},
		{"whitespace only collapses to empty", "   ", false},
		{"parent-domain form", ".acme.com", false},
		{"bare host", "acme.com", false},
		{"subdomain", ".auth.acme.com", false},

		// Reject — format
		{"contains space", ".acme com", true},
		{"contains slash", ".acme.com/path", true},
		{"only a dot", ".", true},

		// Reject — public suffix (hardcoded shortlist)
		{"github.io rejected", ".github.io", true},
		{"github.io bare host rejected", "github.io", true},
		{"vercel.app rejected", ".vercel.app", true},
		{"netlify.app rejected", ".netlify.app", true},
		{"pages.dev rejected", "pages.dev", true},
		{"herokuapp.com rejected", "herokuapp.com", true},

		// Reject — multi-label PSL entries the hardcoded shortlist
		// missed. The publicsuffix library covers these via the
		// authoritative Mozilla PSL.
		{"co.uk rejected", "co.uk", true},
		{"co.uk leading dot rejected", ".co.uk", true},
		{"com.br rejected", "com.br", true},
		{"co.jp rejected", "co.jp", true},
		{"ne.jp rejected", "ne.jp", true},
		{"s3.amazonaws.com rejected", "s3.amazonaws.com", true},

		// Accept — registrable domains under those public suffixes
		{"acme.co.uk accepted", ".acme.co.uk", false},
		{"sub.acme.co.uk accepted", "sub.acme.co.uk", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateCookieDomain(c.input)
			if c.wantErr && err == nil {
				t.Errorf("validateCookieDomain(%q) = nil, want error", c.input)
			}
			if !c.wantErr && err != nil {
				t.Errorf("validateCookieDomain(%q) = %v, want nil", c.input, err)
			}
		})
	}
}
