package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/rs/zerolog/log"
)

type DeliveryConfigItem struct {
	Key  string               `json:"key"`
	Type core.ConfigValueType `json:"type"`

	// For public/private only. Omitted for secrets.
	Value json.RawMessage `json:"value,omitempty"`

	// For secrets only. Omitted for public/private.
	IsSet *bool `json:"isSet,omitempty"`

	// Envelope is the encrypted secret payload (the SecretEnvelopeV1
	// shape — see core/repo/configKeysRepo.go). Only set on the
	// server-API delivery path (GetDeliveryForServer); browser-side
	// runtime delivery (GetAppData) never returns secrets at all.
	// The server API is API-key-authenticated, so an attacker would
	// need both the API key AND the customer's private decryption
	// key to read plaintext.
	Envelope json.RawMessage `json:"envelope,omitempty"`
}

type DeliveryFlagItem struct {
	Key     string   `json:"key"`
	Enabled bool     `json:"enabled"`
	RoleIDs []string `json:"roleIds,omitempty"` // if set, flag only applies to users with one of these roles
}

type DeliveryConfigBuckets struct {
	Public  []DeliveryConfigItem `json:"public"`
	Private []DeliveryConfigItem `json:"private"`
	Secrets []DeliveryConfigItem `json:"secrets"`
}

type DeliveryFlagBuckets struct {
	Client []DeliveryFlagItem `json:"client"`
	Server []DeliveryFlagItem `json:"server"`
}

type DeliveryResponse struct {
	WorkspaceID string `json:"workspaceId"`
	ProductID   string `json:"productId"`
	AppID       string `json:"appId"`

	UpdatedAt time.Time `json:"updatedAt"`

	Config DeliveryConfigBuckets `json:"config"`
	Flags  DeliveryFlagBuckets   `json:"flags"`
}

func (handler *RequestHandler) GetDeliveryForServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ws, ok := core.WorkspaceFromContext(ctx)
	if !ok || ws == nil {
		WriteError(w, r, "error.unauthorized", http.StatusUnauthorized)
		return
	}
	project, ok := core.ProductFromContext(ctx)
	if !ok || project == nil {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}
	app, ok := core.AppFromContext(ctx)
	if !ok || app == nil {
		WriteError(w, r, "error.forbidden", http.StatusForbidden)
		return
	}

	// helper to max time
	maxT := func(a, b time.Time) time.Time {
		if a.IsZero() {
			return b
		}
		if b.After(a) {
			return b
		}
		return a
	}

	updatedAt := time.Time{}

	// -----------------------------
	// CONFIG (keys + values for env)
	// -----------------------------
	keys, err := handler.repo.GetConfigKeysByProductID(ctx, project.ID)
	if err != nil {
		log.Err(err).Msg("failed to get config keys for delivery")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	values, err := handler.repo.GetConfigValuesByProductID(ctx, project.ID)
	if err != nil {
		log.Err(err).Msg("failed to get config values for delivery")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// Map: configKeyID -> (present?, valueJSON, updatedAt)
	type cvInfo struct {
		present   bool
		valueJSON json.RawMessage
		updatedAt time.Time
	}
	cvByKey := make(map[string]cvInfo, 64)
	for i := range values {
		cv := values[i]
		if cv.AppID != app.ID {
			continue
		}
		cvByKey[cv.ConfigKeyID.String()] = cvInfo{
			present:   true,
			valueJSON: cv.ValueJSON,
			updatedAt: cv.UpdatedAt,
		}
	}

	cfg := DeliveryConfigBuckets{
		Public:  make([]DeliveryConfigItem, 0, 16),
		Private: make([]DeliveryConfigItem, 0, 16),
		Secrets: make([]DeliveryConfigItem, 0, 16),
	}

	for i := range keys {
		ck := keys[i]

		// Only deliver active keys
		if ck.Status != "active" {
			continue
		}

		updatedAt = maxT(updatedAt, ck.UpdatedAt)

		info, exists := cvByKey[ck.ID.String()]
		if exists && !info.updatedAt.IsZero() {
			updatedAt = maxT(updatedAt, info.updatedAt)
		}

		switch ck.Exposure {
		case core.ConfigExposurePublic:
			item := DeliveryConfigItem{
				Key:  ck.Key,
				Type: ck.ValueType,
			}
			if exists && len(info.valueJSON) > 0 && string(info.valueJSON) != "null" {
				item.Value = info.valueJSON
			}
			cfg.Public = append(cfg.Public, item)

		case core.ConfigExposurePrivate:
			item := DeliveryConfigItem{
				Key:  ck.Key,
				Type: ck.ValueType,
			}
			if exists && len(info.valueJSON) > 0 && string(info.valueJSON) != "null" {
				item.Value = info.valueJSON
			}
			cfg.Private = append(cfg.Private, item)

		case core.ConfigExposureSecret:
			// Server delivery: pass the encrypted envelope through so
			// SDK customers (holding the workspace private key) can
			// decrypt server-side. The envelope is the bytes the
			// browser produced on save (`SecretEnvelopeV1`); we never
			// see plaintext here. Browser/runtime delivery
			// (GetAppData) returns no secret entries at all, so the
			// envelope only ships to API-key-authenticated callers.
			isSet := exists && info.present
			item := DeliveryConfigItem{
				Key:   ck.Key,
				Type:  ck.ValueType,
				IsSet: &isSet,
			}
			if isSet && len(info.valueJSON) > 0 && string(info.valueJSON) != "null" {
				item.Envelope = info.valueJSON
			}
			cfg.Secrets = append(cfg.Secrets, item)

		default:
			// Unknown exposure: skip (defensive)
			continue
		}
	}

	// -----------------------------
	// FLAGS (metadata + evaluated)
	// -----------------------------
	ffs, err := handler.repo.GetFeatureFlagsByProductID(ctx, project.ID)
	if err != nil {
		log.Err(err).Msg("failed to get feature flags for delivery")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	evaluated, err := handler.repo.GetEvaluatedFeatureFlagsForProductAndApp(ctx, project.ID, app.ID)
	if err != nil {
		log.Err(err).Msg("failed to get evaluated feature flags for delivery")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}
	type evalResult struct {
		Enabled bool
		RoleIDs []uuid.UUID
	}
	evalByKey := make(map[string]evalResult, len(evaluated))
	for i := range evaluated {
		evalByKey[evaluated[i].Key] = evalResult{Enabled: evaluated[i].Enabled, RoleIDs: evaluated[i].RoleIDs}
	}

	flags := DeliveryFlagBuckets{
		Client: make([]DeliveryFlagItem, 0, 16),
		Server: make([]DeliveryFlagItem, 0, 16),
	}

	for i := range ffs {
		ff := ffs[i]

		// Only deliver active flags
		if ff.Status != "active" {
			continue
		}

		updatedAt = maxT(updatedAt, ff.UpdatedAt)

		eval, ok := evalByKey[ff.Key]
		enabled := ff.DefaultEnabled
		if ok {
			enabled = eval.Enabled
		}

		item := DeliveryFlagItem{
			Key:     ff.Key,
			Enabled: enabled,
		}
		// Include role targeting info for server consumers
		if ok && len(eval.RoleIDs) > 0 {
			roleStrs := make([]string, len(eval.RoleIDs))
			for j, rid := range eval.RoleIDs {
				roleStrs[j] = rid.String()
			}
			item.RoleIDs = roleStrs
		}

		switch ff.Scope {
		case core.FeatureFlagScopeClient:
			flags.Client = append(flags.Client, item)
		case core.FeatureFlagScopeServer:
			flags.Server = append(flags.Server, item)
		default:
			// Unknown scope: skip
			continue
		}
	}

	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}

	resp := DeliveryResponse{
		WorkspaceID: ws.ID.String(),
		ProductID:   project.ID.String(),
		AppID:       app.ID.String(),
		UpdatedAt:   updatedAt,
		Config:      cfg,
		Flags:       flags,
	}

	body, err := json.Marshal(resp)
	if err != nil {
		log.Err(err).Msg("failed to marshal delivery response")
		WriteError(w, r, "error.internalError", http.StatusInternalServerError)
		return
	}

	// ETag over the response body so customer servers can poll this endpoint
	// cheaply: if config and flags are unchanged we return 304 with no payload.
	// Hashing the body (rather than trusting updatedAt) also catches deletes,
	// which don't bump any row's updated_at.
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")

	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// etagMatches reports whether an If-None-Match header value matches the given
// ETag, per RFC 7232: "*" matches anything, otherwise the header is a
// comma-separated list of candidates compared with weak semantics (the W/
// prefix is ignored for the comparison).
func etagMatches(ifNoneMatch, etag string) bool {
	ifNoneMatch = strings.TrimSpace(ifNoneMatch)
	if ifNoneMatch == "" {
		return false
	}
	if ifNoneMatch == "*" {
		return true
	}
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		c := strings.TrimSpace(candidate)
		c = strings.TrimPrefix(c, "W/")
		if c == etag {
			return true
		}
	}
	return false
}
