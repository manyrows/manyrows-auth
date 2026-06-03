package db

import "testing"

// resolveSchema applies the default-schema fallback. A fresh install (no
// MANYROWS_DB_SCHEMA) must land on "manyrowsauth"; any explicit value —
// including the legacy "manyrows" — is handed through unchanged.
func TestResolveSchema(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		want       string
	}{
		{"empty falls back to the new default", "", "manyrowsauth"},
		{"explicit legacy name is respected", "manyrows", "manyrows"},
		{"explicit custom name is respected", "tenant_a", "tenant_a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveSchema(tt.configured); got != tt.want {
				t.Errorf("resolveSchema(%q) = %q, want %q", tt.configured, got, tt.want)
			}
		})
	}
}

// shouldRenameLegacySchema decides whether to ALTER SCHEMA manyrows RENAME
// TO manyrowsauth. It must fire only for a genuine legacy ManyRows install
// that hasn't already been migrated, and must never clobber an existing
// target or hijack an unrelated schema that happens to be named "manyrows".
func TestShouldRenameLegacySchema(t *testing.T) {
	tests := []struct {
		name         string
		targetExists bool
		legacyExists bool
		legacyIsOurs bool
		want         bool
	}{
		{"fresh install: nothing to migrate", false, false, false, false},
		{"legacy ManyRows schema present, target absent: rename", false, true, true, true},
		{"target already exists: never clobber", true, true, true, false},
		{"schema named manyrows but not ours: never hijack", false, true, false, false},
		{"both present: target wins, no rename", true, true, true, false},
		{"only target exists: nothing to migrate", true, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldRenameLegacySchema(tt.targetExists, tt.legacyExists, tt.legacyIsOurs)
			if got != tt.want {
				t.Errorf("shouldRenameLegacySchema(target=%v, legacy=%v, ours=%v) = %v, want %v",
					tt.targetExists, tt.legacyExists, tt.legacyIsOurs, got, tt.want)
			}
		})
	}
}
