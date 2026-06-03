package db

import "testing"

// resolveSchema applies the default-schema fallback. A fresh install (no
// MANYROWS_DB_SCHEMA) must land on "manyrowsauth"; any explicit value is
// handed through unchanged.
func TestResolveSchema(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		want       string
	}{
		{"empty falls back to the default", "", "manyrowsauth"},
		{"explicit name is respected", "manyrows", "manyrows"},
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
