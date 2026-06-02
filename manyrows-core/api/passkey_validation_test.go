package api

import (
	"strings"
	"testing"
)

func TestValidateRPIDAgainstOrigins(t *testing.T) {
	tests := []struct {
		name      string
		rpid      string
		origins   []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "apex domain covers itself",
			rpid:    "drumkingdom.com",
			origins: []string{"https://drumkingdom.com"},
			wantErr: false,
		},
		{
			name:    "apex covers subdomain",
			rpid:    "drumkingdom.com",
			origins: []string{"https://app.drumkingdom.com", "https://staging.drumkingdom.com"},
			wantErr: false,
		},
		{
			name:    "apex covers itself plus subdomains",
			rpid:    "example.com",
			origins: []string{"https://example.com", "https://www.example.com", "https://app.example.com"},
			wantErr: false,
		},
		{
			name:    "subdomain RPID covers further subdomains but not parent",
			rpid:    "app.example.com",
			origins: []string{"https://app.example.com", "https://internal.app.example.com"},
			wantErr: false,
		},
		{
			name:      "subdomain RPID rejects parent domain origin",
			rpid:      "app.example.com",
			origins:   []string{"https://example.com"},
			wantErr:   true,
			errSubstr: "not under RPID",
		},
		{
			name:      "rejects unrelated TLD",
			rpid:      "drumkingdom.com",
			origins:   []string{"https://drumkingdom.com", "https://drumkingdom-staging.io"},
			wantErr:   true,
			errSubstr: "not under RPID",
		},
		{
			name:      "rejects bare TLD as RPID",
			rpid:      "com",
			origins:   []string{"https://example.com"},
			wantErr:   true,
			errSubstr: "registrable",
		},
		{
			name:      "rejects empty RPID",
			rpid:      "",
			origins:   []string{"https://example.com"},
			wantErr:   true,
			errSubstr: "required",
		},
		{
			name:    "localhost is allowed without public-suffix check",
			rpid:    "localhost",
			origins: []string{"http://localhost:5173", "http://localhost:3000"},
			wantErr: false,
		},
		{
			name:    "localhost origins coexist with public RPID",
			rpid:    "drumkingdom.com",
			origins: []string{"https://drumkingdom.com", "http://localhost:5173"},
			wantErr: false,
		},
		{
			name:      "rejects when one of many origins is wrong",
			rpid:      "example.com",
			origins:   []string{"https://example.com", "https://other.io"},
			wantErr:   true,
			errSubstr: "not under RPID",
		},
		{
			name:      "rejects malformed origin",
			rpid:      "example.com",
			origins:   []string{"not-a-url"},
			wantErr:   true,
			errSubstr: "invalid CORS origin",
		},
		{
			name:    "trims and lowercases input",
			rpid:    "  Example.COM  ",
			origins: []string{"https://example.com"},
			wantErr: false,
		},
		{
			name:    "leading dot is stripped",
			rpid:    ".example.com",
			origins: []string{"https://example.com"},
			wantErr: false,
		},
		{
			name:    "uppercase host is normalized",
			rpid:    "example.com",
			origins: []string{"https://EXAMPLE.com"},
			wantErr: false,
		},
		{
			name:      "rejects sibling subdomain that does not share parent",
			rpid:      "a.example.com",
			origins:   []string{"https://b.example.com"},
			wantErr:   true,
			errSubstr: "not under RPID",
		},
		{
			name:    "co.uk-style multipart TLD at apex is registrable",
			rpid:    "example.co.uk",
			origins: []string{"https://example.co.uk", "https://app.example.co.uk"},
			wantErr: false,
		},
		{
			name:      "bare co.uk is not registrable",
			rpid:      "co.uk",
			origins:   []string{"https://example.co.uk"},
			wantErr:   true,
			errSubstr: "registrable",
		},
		{
			name:    "IDN unicode RPID is normalized to punycode",
			rpid:    "bücher.example",
			origins: []string{"https://bücher.example"},
			wantErr: false,
		},
		{
			name:    "IDN punycode RPID matches unicode origin",
			rpid:    "xn--bcher-kva.example",
			origins: []string{"https://bücher.example", "https://app.bücher.example"},
			wantErr: false,
		},
		{
			name:      "IPv4 origin rejected (passkeys require domains)",
			rpid:      "example.com",
			origins:   []string{"https://192.0.2.1"},
			wantErr:   true,
			errSubstr: "not under RPID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRPIDAgainstOrigins(tt.rpid, tt.origins)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.errSubstr)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error to contain %q, got: %v", tt.errSubstr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestAuthenticatorNameForAAGUID(t *testing.T) {
	if got := authenticatorNameForAAGUID(nil); got != "" {
		t.Errorf("nil AAGUID should return empty, got %q", got)
	}
}
