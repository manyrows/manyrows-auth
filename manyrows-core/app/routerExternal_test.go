package app

import "testing"

// TestIsReadOnlyCustomMethod exercises the allowlist gate that lets read-scoped
// API keys reach POST /users:lookup. A simple HasSuffix on ":lookup" is too
// broad — a mutating route whose trailing param ends in ":lookup"
// (e.g. DELETE /roles/evil:lookup) would pass it.  The segment-structure match
// must only match the real route shape .../apps/{appId}/users:lookup.

func TestIsReadOnlyCustomMethod(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// --- real route: must be allowed ---
		{"/x/acme/api/v1/apps/00000000-0000-0000-0000-000000000001/users:lookup", true},

		// --- spoof: DELETE /roles/{slug} where slug ends in ":lookup" ---
		{"/x/acme/api/v1/apps/00000000-0000-0000-0000-000000000001/roles/evil:lookup", false},

		// --- extra segment before users:lookup — seg[n-3] would be a UUID, not "apps" ---
		{"/x/acme/api/v1/apps/00000000-0000-0000-0000-000000000001/config/users:lookup", false},

		// --- too short: no apps segment two positions back ---
		{"/users:lookup", false},
		{"/apps/users:lookup", false},

		// --- wrong final segment (not users:lookup) ---
		{"/x/acme/api/v1/apps/00000000-0000-0000-0000-000000000001/users", false},
		{"/x/acme/api/v1/apps/00000000-0000-0000-0000-000000000001/users:batch", false},

		// --- almost right: seg[n-3] is "v1" not "apps" (path /x/a/api/v1/apps/users:lookup) ---
		{"/x/a/api/v1/apps/users:lookup", false},
	}

	for _, tc := range cases {
		got := isReadOnlyCustomMethod(tc.path)
		if got != tc.want {
			t.Errorf("isReadOnlyCustomMethod(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
