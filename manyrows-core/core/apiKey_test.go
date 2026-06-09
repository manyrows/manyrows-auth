package core

import (
	"testing"
	"time"
)

func TestAPIKey_IsExpired(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	if (&APIKey{}).IsExpired(now) {
		t.Error("a key with no expiry must never be expired")
	}
	if !(&APIKey{ExpiresAt: &past}).IsExpired(now) {
		t.Error("a key whose expiry is in the past must be expired")
	}
	if (&APIKey{ExpiresAt: &future}).IsExpired(now) {
		t.Error("a key whose expiry is in the future must not be expired")
	}
}

func TestAPIKey_AllowsWrite(t *testing.T) {
	if !(&APIKey{Scope: APIKeyScopeReadWrite}).AllowsWrite() {
		t.Error("read_write scope must allow writes")
	}
	if (&APIKey{Scope: APIKeyScopeRead}).AllowsWrite() {
		t.Error("read scope must NOT allow writes")
	}
	// Defensive: an unset scope retains the historical full-access behaviour.
	if !(&APIKey{}).AllowsWrite() {
		t.Error("unset scope should retain full access (backward compatible)")
	}
}

func TestValidAPIKeyScope(t *testing.T) {
	if !ValidAPIKeyScope(APIKeyScopeRead) || !ValidAPIKeyScope(APIKeyScopeReadWrite) {
		t.Error("read and read_write must be valid")
	}
	if ValidAPIKeyScope("admin") || ValidAPIKeyScope("") {
		t.Error("unknown/empty scopes must be invalid")
	}
}
