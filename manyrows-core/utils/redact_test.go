package utils

import "testing"

func TestMaskEmail(t *testing.T) {
	cases := map[string]string{
		"alice@example.com": "a***e@example.com",
		"a@example.com":     "a***@example.com",
		"not-an-email":      "***",
		"":                  "***",
	}
	for in, want := range cases {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAnonymizeIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":          "203.0.113.0",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1::",
		"not-an-ip":            "",
		"":                     "",
	}
	for in, want := range cases {
		if got := AnonymizeIP(in); got != want {
			t.Errorf("AnonymizeIP(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLogIP_Toggle(t *testing.T) {
	SetAnonymizeIPInLogs(true)
	if got := LogIP("203.0.113.7"); got != "203.0.113.0" {
		t.Errorf("LogIP on = %q", got)
	}
	SetAnonymizeIPInLogs(false)
	if got := LogIP("203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("LogIP off = %q", got)
	}
	SetAnonymizeIPInLogs(true) // restore default
}

func TestQueryString_MasksEmail(t *testing.T) {
	got := QueryString("email=alice@example.com&id=42")
	if got == "email=alice@example.com&id=42" {
		t.Fatalf("QueryString did not mask: %q", got)
	}
	if !contains(got, "id=42") {
		t.Fatalf("QueryString dropped non-email param: %q", got)
	}
	if contains(got, "alice@example.com") {
		t.Fatalf("QueryString left raw email: %q", got)
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
