package api_test

import (
	"encoding/json"
	"manyrows-core/core"
	"strings"
	"testing"
)

func TestValidateFieldValue_String(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid string", `"hello"`, false},
		{"empty string", `""`, false},
		{"number not string", `42`, true},
		{"bool not string", `true`, true},
		{"null", `null`, true},
		{"empty", ``, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := core.ValidateFieldValue(core.UserFieldValueTypeString, json.RawMessage(tt.value))
			if tt.wantErr && msg == "" {
				t.Error("expected error, got none")
			}
			if !tt.wantErr && msg != "" {
				t.Errorf("expected no error, got %q", msg)
			}
		})
	}
}

func TestValidateFieldValue_StringMaxLength(t *testing.T) {
	long := `"` + strings.Repeat("a", 1001) + `"`
	msg := core.ValidateFieldValue(core.UserFieldValueTypeString, json.RawMessage(long))
	if msg == "" {
		t.Error("expected error for string over 1000 chars")
	}

	ok := `"` + strings.Repeat("a", 1000) + `"`
	msg = core.ValidateFieldValue(core.UserFieldValueTypeString, json.RawMessage(ok))
	if msg != "" {
		t.Errorf("expected no error for 1000 char string, got %q", msg)
	}
}

func TestValidateFieldValue_Bool(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"true", `true`, false},
		{"false", `false`, false},
		{"string not bool", `"true"`, true},
		{"number not bool", `1`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := core.ValidateFieldValue(core.UserFieldValueTypeBool, json.RawMessage(tt.value))
			if tt.wantErr && msg == "" {
				t.Error("expected error, got none")
			}
			if !tt.wantErr && msg != "" {
				t.Errorf("expected no error, got %q", msg)
			}
		})
	}
}

func TestValidateFieldValue_Date(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"YYYY-MM-DD", `"2026-04-04"`, false},
		{"ISO 8601", `"2026-04-04T10:30:00Z"`, false},
		{"not a date", `"hello"`, true},
		{"number", `20260404`, true},
		{"partial date", `"2026-04"`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := core.ValidateFieldValue(core.UserFieldValueTypeDate, json.RawMessage(tt.value))
			if tt.wantErr && msg == "" {
				t.Error("expected error, got none")
			}
			if !tt.wantErr && msg != "" {
				t.Errorf("expected no error, got %q", msg)
			}
		})
	}
}
