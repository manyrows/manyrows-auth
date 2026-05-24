package core

import (
	"encoding/json"
	"time"

	"github.com/gofrs/uuid/v5"
)

const (
	ConfigExposurePublic  string = "public"  // safe to return to browser/runtime public endpoint
	ConfigExposurePrivate string = "private" // only return to server/runtime private endpoint
	ConfigExposureSecret  string = "secret"  // encrypted at rest; never return plaintext in admin UI
)

// ConfigValueType defines the allowed shape of a config value for a key.
// This drives:
// - UI input type (text/number/switch/array editor)
// - server validation on write
type ConfigValueType string

const (
	// scalars
	ConfigValueTypeString  ConfigValueType = "string"
	ConfigValueTypeInt     ConfigValueType = "int"
	ConfigValueTypeDecimal ConfigValueType = "decimal"
	ConfigValueTypeBool    ConfigValueType = "bool"

	// arrays
	ConfigValueTypeStringArray  ConfigValueType = "string[]"
	ConfigValueTypeIntArray     ConfigValueType = "int[]"
	ConfigValueTypeDecimalArray ConfigValueType = "decimal[]"
	ConfigValueTypeBoolArray    ConfigValueType = "bool[]"

	// escape hatch (optional, but useful)
	ConfigValueTypeJSON ConfigValueType = "json"
)

func (t ConfigValueType) IsValid() bool {
	switch t {
	case ConfigValueTypeString,
		ConfigValueTypeInt,
		ConfigValueTypeDecimal,
		ConfigValueTypeBool,
		ConfigValueTypeStringArray,
		ConfigValueTypeIntArray,
		ConfigValueTypeDecimalArray,
		ConfigValueTypeBoolArray,
		ConfigValueTypeJSON:
		return true
	default:
		return false
	}
}

// ConfigKey is the project-level definition (metadata) of a config entry.
type ConfigKey struct {
	ID        uuid.UUID `json:"id"`
	ProductID uuid.UUID `json:"productId"`

	// Stable identifier used by SDKs/integrations
	Key string `json:"key"` // e.g. "PUBLIC_BASE_URL", "MAX_RETRIES", "ALLOWED_COUNTRIES"

	Exposure  string          `json:"exposure"`  // "public" | "private" | "secret"
	ValueType ConfigValueType `json:"valueType"` // "string" | "int" | "decimal" | "bool" | "...[]"
	Status    string          `json:"status"`    // "active" | "archived"

	// Optional human description (UI/help text)
	Description *string `json:"description,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	CreatedBy uuid.UUID `json:"createdBy"`
}

// ConfigValue is stored sparsely: only exists when set.
// Unset == no row in DB.
//
// Storage rules:
// - For public/private: store ValueJSON (jsonb in DB) and return it via JSON.
// - For secrets: store ValueEncrypted bytes (represents encrypted JSON) and never return plaintext in admin UI.
type ConfigValue struct {
	ID uuid.UUID `json:"id"`

	ProductID   uuid.UUID `json:"productId"`
	AppID       uuid.UUID `json:"appId"`
	ConfigKeyID uuid.UUID `json:"configKeyId"`

	// Public/private: JSON value (string/number/bool/array/etc). Nil means unset (but note: "unset" normally means no row).
	// We use RawMessage so we can roundtrip without losing typing.
	ValueJSON json.RawMessage `json:"value,omitempty"`

	// Secret: encrypted JSON bytes. Never exposed via JSON.
	ValueEncrypted []byte `json:"-"`

	UpdatedAt time.Time `json:"updatedAt"`
	UpdatedBy uuid.UUID `json:"updatedBy"`
}

// PublicConfigItem is a frontend-safe config payload (public exposure only).
// Value is nil when not set for this app.
// (Using RawMessage allows types to survive: string/number/bool/array.)
type PublicConfigItem struct {
	Key   string          `json:"key"`
	Type  ConfigValueType `json:"type"`
	Value json.RawMessage `json:"value,omitempty"`
}
