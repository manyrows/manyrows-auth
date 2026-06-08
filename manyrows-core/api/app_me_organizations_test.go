package api_test

import (
	"encoding/json"
	"strings"
	"testing"

	"manyrows-core/api"
	"manyrows-core/core"
)

// appData must let an SDK tell "organizations feature off" apart from
// "org-enabled but you belong to none": the former omits the key entirely
// (preserving legacy byte-for-byte appData), the latter emits an empty list.
func TestAppMeAppPart_OrganizationsContract(t *testing.T) {
	// org-disabled app → nil → key omitted.
	off := api.AppMeAppPart{Name: "x"}
	b, err := json.Marshal(off)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "organizations") {
		t.Errorf("org-disabled app must omit organizations, got %s", b)
	}

	// org-enabled, zero orgs → present as [] (not null, not omitted).
	empty := []core.OrganizationMembershipView{}
	enabled := api.AppMeAppPart{Name: "x", Organizations: &empty}
	b2, err := json.Marshal(enabled)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b2), `"organizations":[]`) {
		t.Errorf("org-enabled 0-org must emit empty list, got %s", b2)
	}
}
