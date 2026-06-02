package core

import (
	"encoding/json"
	"time"

	"github.com/gofrs/uuid/v5"
)

// UserFieldValueType defines the allowed shape of a user field value.
type UserFieldValueType string

const (
	UserFieldValueTypeString UserFieldValueType = "string"
	UserFieldValueTypeBool   UserFieldValueType = "bool"
	UserFieldValueTypeDate   UserFieldValueType = "date"
)

func (t UserFieldValueType) IsValid() bool {
	switch t {
	case UserFieldValueTypeString,
		UserFieldValueTypeBool,
		UserFieldValueTypeDate:
		return true
	}
	return false
}

const (
	UserFieldVisibilityClient string = "client" // visible via AppKit SDK
	UserFieldVisibilityServer string = "server" // admin + server SDK only
)

// UserField is a pool-level schema definition for user metadata.
// Scoped to the user_pool because identity (the row a value attaches
// to) is pool-scoped. Apps that share a pool share these fields.
type UserField struct {
	ID           uuid.UUID          `json:"id"`
	UserPoolID   uuid.UUID          `json:"userPoolId"`
	Key          string             `json:"key"`
	ValueType    UserFieldValueType `json:"valueType"`
	Visibility   string             `json:"visibility"`   // "client" | "server"
	UserEditable bool               `json:"userEditable"` // true = user can write via client SDK
	Label        string             `json:"label"`        // label shown to the user
	Status       string             `json:"status"`       // "active" | "archived"
	CreatedAt    time.Time          `json:"createdAt"`
	UpdatedAt    time.Time          `json:"updatedAt"`
	CreatedBy    uuid.UUID          `json:"createdBy"`
}

// UserFieldValue stores a single field value for a user. Keyed on
// (user_id, user_field_id). user_id implies the pool, so there's no
// separate scope column.
type UserFieldValue struct {
	ID          uuid.UUID       `json:"id"`
	UserID      uuid.UUID       `json:"userId"`
	UserFieldID uuid.UUID       `json:"userFieldId"`
	ValueJSON   json.RawMessage `json:"value,omitempty"`
	UpdatedAt   time.Time       `json:"updatedAt"`
	UpdatedBy   uuid.UUID       `json:"updatedBy"`
}

// ValidateFieldValue checks that valueJSON is the correct JSON type for the field's valueType.
// Returns a human-readable error string, or "" if valid.
func ValidateFieldValue(vt UserFieldValueType, raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return "value is required"
	}

	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "invalid JSON value"
	}

	switch vt {
	case UserFieldValueTypeString:
		s, ok := v.(string)
		if !ok {
			return "expected a string value"
		}
		if len(s) > 1000 {
			return "string value must be 1000 characters or less"
		}
	case UserFieldValueTypeBool:
		if _, ok := v.(bool); !ok {
			return "expected a boolean value"
		}
	case UserFieldValueTypeDate:
		s, ok := v.(string)
		if !ok {
			return "expected a date string (ISO 8601)"
		}
		// Accept YYYY-MM-DD or full ISO 8601 datetime
		if _, err := time.Parse("2006-01-02", s); err != nil {
			if _, err := time.Parse(time.RFC3339, s); err != nil {
				return "invalid date format, expected YYYY-MM-DD or ISO 8601"
			}
		}
	}
	return ""
}

// ClientUserFieldItem is the shape returned to the AppKit SDK (visibility=client only).
type ClientUserFieldItem struct {
	Key   string             `json:"key"`
	Type  UserFieldValueType `json:"type"`
	Label string             `json:"label"`
	Value json.RawMessage    `json:"value,omitempty"`
}
