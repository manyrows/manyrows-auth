package api

import (
	"strings"
	"testing"

	"github.com/gofrs/uuid/v5"
)

// Pure-function unit tests for the magic-link helpers — no DB, no
// router, no fixtures. Catches regressions in URL shape and namespacing
// that the integration tests would also catch but more slowly and with
// noisier output.

func TestAppLoginMagicPurpose_NamespacedByApp(t *testing.T) {
	a := uuid.Must(uuid.NewV4())
	b := uuid.Must(uuid.NewV4())
	pa := appLoginMagicPurpose(a)
	pb := appLoginMagicPurpose(b)
	if pa == pb {
		t.Fatalf("two app IDs produced the same purpose %q — magic-link rows must be app-scoped", pa)
	}
	if !strings.HasPrefix(pa, "app_login:") {
		t.Errorf("purpose %q missing required prefix", pa)
	}
	if !strings.Contains(pa, a.String()) {
		t.Errorf("purpose %q should embed the app ID", pa)
	}
}

func TestBuildMagicLinkConsumeURL_Shape(t *testing.T) {
	appID := uuid.Must(uuid.NewV4())
	got := buildMagicLinkConsumeURL("https://api.example.com", "ws-slug", appID, "raw-token-xyz", false)
	want := "https://api.example.com/x/ws-slug/apps/" + appID.String() + "/auth/magic-link?token=raw-token-xyz"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

func TestBuildMagicLinkConsumeURL_RememberMeFlag(t *testing.T) {
	appID := uuid.Must(uuid.NewV4())
	got := buildMagicLinkConsumeURL("https://api.example.com", "ws", appID, "tok", true)
	if !strings.Contains(got, "r=1") {
		t.Errorf("rememberMe=true should produce r=1, got %q", got)
	}
	got2 := buildMagicLinkConsumeURL("https://api.example.com", "ws", appID, "tok", false)
	if strings.Contains(got2, "r=1") {
		t.Errorf("rememberMe=false should omit r=1, got %q", got2)
	}
}

func TestBuildMagicLinkConsumeURL_StripsTrailingSlash(t *testing.T) {
	appID := uuid.Must(uuid.NewV4())
	got := buildMagicLinkConsumeURL("https://api.example.com/", "ws", appID, "tok", false)
	if strings.Contains(got, ".com//x/") {
		t.Errorf("trailing slash on baseURL leaked into output: %q", got)
	}
}

func TestAppendFragment_ReplacesExisting(t *testing.T) {
	got := appendFragment("https://app.example.com/path?q=1#oldfrag", "mr_session=abc")
	if !strings.HasSuffix(got, "#mr_session=abc") {
		t.Errorf("expected new fragment to replace old, got %q", got)
	}
	if strings.Contains(got, "oldfrag") {
		t.Errorf("old fragment should be gone, got %q", got)
	}
	if !strings.Contains(got, "?q=1") {
		t.Errorf("query string should be preserved, got %q", got)
	}
}

func TestAppendFragment_PreservesQuery(t *testing.T) {
	got := appendFragment("https://app.example.com/?next=/dashboard", "mr_session=tok")
	if !strings.Contains(got, "next=/dashboard") {
		t.Errorf("query lost: %q", got)
	}
	if !strings.Contains(got, "#mr_session=tok") {
		t.Errorf("fragment missing: %q", got)
	}
}

func TestAppendFragment_FallbackOnUnparseable(t *testing.T) {
	// Pass a string that url.Parse rejects — implementation should
	// still produce something usable rather than dropping the redirect.
	got := appendFragment("://broken", "k=v")
	if !strings.Contains(got, "k=v") {
		t.Errorf("unparseable input dropped fragment: %q", got)
	}
}
