package repo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
)

// ----------------------------
// Config Keys
// ----------------------------

func (r *Repo) GetConfigKeysByProjectID(ctx context.Context, projectID uuid.UUID) ([]core.ConfigKey, error) {
	const q = `
		select
			id,
			project_id,
			key,
			description,
			exposure,
			value_type,
			status,
			created_at,
			updated_at,
			created_by_account_id
		from config_keys
		where project_id = $1
		order by created_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.ConfigKey, 0, 32)
	for rows.Next() {
		var ck core.ConfigKey
		var desc *string
		var exposure string
		var vt string
		if err := rows.Scan(
			&ck.ID,
			&ck.ProjectID,
			&ck.Key,
			&desc,
			&exposure,
			&vt,
			&ck.Status,
			&ck.CreatedAt,
			&ck.UpdatedAt,
			&ck.CreatedBy,
		); err != nil {
			return nil, err
		}
		ck.Description = desc
		ck.Exposure = exposure
		ck.ValueType = core.ConfigValueType(vt)
		out = append(out, ck)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) CreateConfigKey(ctx context.Context, ck core.ConfigKey) (core.ConfigKey, error) {
	const q = `
		insert into config_keys (
			id,
			project_id,
			key,
			description,
			exposure,
			value_type,
			status,
			created_at,
			updated_at,
			created_by_account_id
		) values (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10
		)
		returning
			id,
			project_id,
			key,
			description,
			exposure,
			value_type,
			status,
			created_at,
			updated_at,
			created_by_account_id
	`

	var out core.ConfigKey
	var desc *string
	var exposure string
	var vt string

	err := r.db.Pool().QueryRow(
		ctx,
		q,
		ck.ID,
		ck.ProjectID,
		ck.Key,
		ck.Description,       // nil => NULL
		ck.Exposure,          // already normalized in handler
		string(ck.ValueType), // store as text
		ck.Status,
		ck.CreatedAt,
		ck.UpdatedAt,
		ck.CreatedBy,
	).Scan(
		&out.ID,
		&out.ProjectID,
		&out.Key,
		&desc,
		&exposure,
		&vt,
		&out.Status,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.CreatedBy,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return core.ConfigKey{}, ErrConflict
		}
		return core.ConfigKey{}, err
	}
	out.Description = desc
	out.Exposure = exposure
	out.ValueType = core.ConfigValueType(vt)
	return out, nil
}

func (r *Repo) GetConfigKeyByID(ctx context.Context, projectID, configKeyID uuid.UUID) (core.ConfigKey, error) {
	const q = `
		select
			id,
			project_id,
			key,
			description,
			exposure,
			value_type,
			status,
			created_at,
			updated_at,
			created_by_account_id
		from config_keys
		where project_id = $1 and id = $2
	`

	var out core.ConfigKey
	var desc *string
	var exposure string
	var vt string

	err := r.db.Pool().QueryRow(ctx, q, projectID, configKeyID).Scan(
		&out.ID,
		&out.ProjectID,
		&out.Key,
		&desc,
		&exposure,
		&vt,
		&out.Status,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.CreatedBy,
	)
	if err != nil {
		if isNoRows(err) {
			return core.ConfigKey{}, ErrNotFound
		}
		return core.ConfigKey{}, err
	}

	out.Description = desc
	out.Exposure = exposure
	out.ValueType = core.ConfigValueType(vt)
	return out, nil
}

func (r *Repo) GetConfigKeyByProjectIDAndKey(ctx context.Context, projectID uuid.UUID, key string) (core.ConfigKey, error) {
	const q = `
		select
			id,
			project_id,
			key,
			description,
			exposure,
			value_type,
			status,
			created_at,
			updated_at,
			created_by_account_id
		from config_keys
		where project_id = $1 and key = $2 and status = 'active'
	`

	var out core.ConfigKey
	var desc *string
	var exposure string
	var vt string

	err := r.db.Pool().QueryRow(ctx, q, projectID, key).Scan(
		&out.ID,
		&out.ProjectID,
		&out.Key,
		&desc,
		&exposure,
		&vt,
		&out.Status,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.CreatedBy,
	)
	if err != nil {
		if isNoRows(err) {
			return core.ConfigKey{}, ErrNotFound
		}
		return core.ConfigKey{}, err
	}

	out.Description = desc
	out.Exposure = exposure
	out.ValueType = core.ConfigValueType(vt)
	return out, nil
}

func (r *Repo) UpdateConfigKey(
	ctx context.Context,
	projectID uuid.UUID,
	configKeyID uuid.UUID,
	description *string,
	exposure *string,
	valueType *core.ConfigValueType,
	status *string,
) (core.ConfigKey, error) {
	set := make([]string, 0, 8)
	args := make([]any, 0, 12)
	argn := 1

	if description != nil {
		set = append(set, `description = $`+itoa(argn))
		if *description == "" {
			args = append(args, nil) // NULL
		} else {
			args = append(args, *description)
		}
		argn++
	}

	if exposure != nil {
		set = append(set, `exposure = $`+itoa(argn))
		args = append(args, *exposure)
		argn++
	}

	if valueType != nil {
		set = append(set, `value_type = $`+itoa(argn))
		args = append(args, string(*valueType))
		argn++
	}

	if status != nil {
		set = append(set, `status = $`+itoa(argn))
		args = append(args, *status)
		argn++
	}

	set = append(set, `updated_at = $`+itoa(argn))
	args = append(args, time.Now().UTC())
	argn++

	args = append(args, projectID, configKeyID)

	q := `
		update config_keys
		set ` + strings.Join(set, ", ") + `
		where project_id = $` + itoa(argn) + ` and id = $` + itoa(argn+1) + `
		returning
			id,
			project_id,
			key,
			description,
			exposure,
			value_type,
			status,
			created_at,
			updated_at,
			created_by_account_id
	`

	var out core.ConfigKey
	var desc *string
	var exp string
	var vt string
	err := r.db.Pool().QueryRow(ctx, q, args...).Scan(
		&out.ID,
		&out.ProjectID,
		&out.Key,
		&desc,
		&exp,
		&vt,
		&out.Status,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.CreatedBy,
	)
	if err != nil {
		if isNoRows(err) {
			return core.ConfigKey{}, ErrNotFound
		}
		if IsUniqueViolation(err) {
			return core.ConfigKey{}, ErrConflict
		}
		return core.ConfigKey{}, err
	}

	out.Description = desc
	out.Exposure = exp
	out.ValueType = core.ConfigValueType(vt)
	return out, nil
}

func (r *Repo) DeleteConfigKey(ctx context.Context, projectID, configKeyID uuid.UUID) error {
	const q = `delete from config_keys where project_id = $1 and id = $2`
	return r.execAffectingOne(ctx, ErrNotFound, q, projectID, configKeyID)
}

// ----------------------------
// Config Values (jsonb + secrets)
// ----------------------------

func (r *Repo) GetConfigValuesByProjectID(ctx context.Context, projectID uuid.UUID) ([]core.ConfigValue, error) {
	const q = `
		select
			id,
			project_id,
			app_id,
			config_key_id,
			value_json,
			updated_at,
			updated_by_account_id
		from config_values
		where project_id = $1
		order by updated_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.ConfigValue, 0, 64)
	for rows.Next() {
		var cv core.ConfigValue
		var v json.RawMessage
		if err := rows.Scan(
			&cv.ID,
			&cv.ProjectID,
			&cv.AppID,
			&cv.ConfigKeyID,
			&v,
			&cv.UpdatedAt,
			&cv.UpdatedBy,
		); err != nil {
			return nil, err
		}
		cv.ValueJSON = v
		out = append(out, cv)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertConfigValueJSON sets a config value for (project, env, key).
//
//   - For public/private: provide valueJSON (secretJSON must be empty/null)
//   - For secret: provide secretJSON as an ENCRYPTED ENVELOPE produced client-side
//     (valueJSON must be empty/null). The server must NEVER receive plaintext.
func (r *Repo) UpsertConfigValueJSON(
	workspaceID uuid.UUID,
	ctx context.Context,
	cv core.ConfigValue,
	valueJSON json.RawMessage,
	secretJSON json.RawMessage,
) (core.ConfigValue, error) {
	valProvided := isNonEmptyJSON(valueJSON)
	secProvided := isNonEmptyJSON(secretJSON)
	if (valProvided && secProvided) || (!valProvided && !secProvided) {
		return core.ConfigValue{}, ErrBadRequest
	}

	// Load key metadata + ensure app belongs to project
	const metaQ = `
		select
			ck.exposure,
			ck.value_type
		from config_keys ck
		join apps a on a.id = $2 and a.project_id = $1
		where ck.id = $3 and ck.project_id = $1
	`
	var exposure string
	var vt string
	if err := r.db.Pool().QueryRow(ctx, metaQ, cv.ProjectID, cv.AppID, cv.ConfigKeyID).Scan(&exposure, &vt); err != nil {
		if isNoRows(err) {
			return core.ConfigValue{}, ErrNotFound
		}
		return core.ConfigValue{}, err
	}

	valueType := core.ConfigValueType(vt)

	// Decide storage
	var storeJSON json.RawMessage
	var encrypted []byte
	var err error

	switch exposure {
	case core.ConfigExposureSecret:
		if !secProvided {
			return core.ConfigValue{}, ErrBadRequest
		}

		// IMPORTANT: secretJSON is NOT plaintext. It is an encrypted envelope created in the browser.
		// We must not validate plaintext type server-side because we never see plaintext.
		// The client should validate against valueType before encrypting.
		_ = valueType

		encrypted, err = r.encryptSecretJSON(ctx, secretJSON, workspaceID)
		if err != nil {
			return core.ConfigValue{}, err
		}
		storeJSON = nil

	default:
		if !valProvided {
			return core.ConfigValue{}, ErrBadRequest
		}
		if !validateValueMatchesType(valueJSON, valueType) {
			return core.ConfigValue{}, ErrBadRequest
		}
		storeJSON = bytes.TrimSpace(valueJSON)
		encrypted = nil
	}

	// Upsert
	const q = `
		insert into config_values (
			id,
			project_id,
			app_id,
			config_key_id,
			value_json,
			value_encrypted,
			updated_at,
			updated_by_account_id
		) values (
			$1,$2,$3,$4,$5,$6,$7,$8
		)
		on conflict (app_id, config_key_id)
		do update set
			project_id = excluded.project_id,
			value_json = excluded.value_json,
			value_encrypted = excluded.value_encrypted,
			updated_at = excluded.updated_at,
			updated_by_account_id = excluded.updated_by_account_id
		returning
			id,
			project_id,
			app_id,
			config_key_id,
			value_json,
			updated_at,
			updated_by_account_id
	`

	var out core.ConfigValue
	var outJSON json.RawMessage

	err = r.db.Pool().QueryRow(
		ctx,
		q,
		cv.ID,
		cv.ProjectID,
		cv.AppID,
		cv.ConfigKeyID,
		storeJSON,
		encrypted,
		cv.UpdatedAt,
		cv.UpdatedBy,
	).Scan(
		&out.ID,
		&out.ProjectID,
		&out.AppID,
		&out.ConfigKeyID,
		&outJSON,
		&out.UpdatedAt,
		&out.UpdatedBy,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return core.ConfigValue{}, ErrConflict
		}
		return core.ConfigValue{}, err
	}

	// Never return secret plaintext
	if exposure == core.ConfigExposureSecret {
		out.ValueJSON = nil
	} else {
		out.ValueJSON = outJSON
	}
	return out, nil
}

func (r *Repo) DeleteConfigValue(ctx context.Context, projectID, configKeyID, appID uuid.UUID) error {
	const q = `
		delete from config_values
		where project_id = $1 and config_key_id = $2 and app_id = $3
	`
	return r.execAffectingOne(ctx, ErrNotFound, q, projectID, configKeyID, appID)
}

// ----------------------------
// Public config delivery (AppData)
// ----------------------------

func (r *Repo) GetPublicConfigForProjectAndApp(
	ctx context.Context,
	projectID uuid.UUID,
	appID uuid.UUID,
) ([]core.PublicConfigItem, error) {
	const q = `
		select
			ck.key,
			ck.value_type,
			cv.value_json
		from config_keys ck
		join apps a
			on a.id = $2 and a.project_id = $1
		join config_values cv
			on cv.app_id = a.id and cv.config_key_id = ck.id
		where
			ck.project_id = $1
			and ck.exposure = $3
			and cv.value_json is not null
		order by ck.key asc
	`

	rows, err := r.db.Pool().Query(ctx, q, projectID, appID, core.ConfigExposurePublic)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.PublicConfigItem, 0, 32)

	for rows.Next() {
		var (
			key string
			vt  string
			raw json.RawMessage
		)
		if err := rows.Scan(&key, &vt, &raw); err != nil {
			return nil, err
		}

		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}

		out = append(out, core.PublicConfigItem{
			Key:   key,
			Type:  core.ConfigValueType(vt),
			Value: raw,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if out == nil {
		out = []core.PublicConfigItem{}
	}
	return out, nil
}

// ----------------------------
// Validation + Encryption helpers
// ----------------------------

func isNonEmptyJSON(b json.RawMessage) bool {
	b = bytes.TrimSpace(b)
	return len(b) > 0 && string(b) != "null"
}

func validateValueMatchesType(raw json.RawMessage, t core.ConfigValueType) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}

	switch t {
	case core.ConfigValueTypeString:
		var v string
		return json.Unmarshal(raw, &v) == nil

	case core.ConfigValueTypeBool:
		var v bool
		return json.Unmarshal(raw, &v) == nil

	case core.ConfigValueTypeInt:
		var n json.Number
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&n); err != nil {
			return false
		}
		_, err := n.Int64()
		return err == nil

	case core.ConfigValueTypeDecimal:
		var n json.Number
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&n); err != nil {
			return false
		}
		_, err := n.Float64()
		return err == nil

	case core.ConfigValueTypeStringArray:
		var v []string
		return json.Unmarshal(raw, &v) == nil

	case core.ConfigValueTypeBoolArray:
		var v []bool
		return json.Unmarshal(raw, &v) == nil

	case core.ConfigValueTypeIntArray:
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var arr []json.Number
		if err := dec.Decode(&arr); err != nil {
			return false
		}
		for _, n := range arr {
			if _, err := n.Int64(); err != nil {
				return false
			}
		}
		return true

	case core.ConfigValueTypeDecimalArray:
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		var arr []json.Number
		if err := dec.Decode(&arr); err != nil {
			return false
		}
		for _, n := range arr {
			if _, err := n.Float64(); err != nil {
				return false
			}
		}
		return true

	case core.ConfigValueTypeJSON:
		var anyVal any
		return json.Unmarshal(raw, &anyVal) == nil

	default:
		return false
	}
}

// SecretEnvelopeV1 is the encrypted payload produced in the browser.
// The server stores it as bytes (value_encrypted) and never sees plaintext.
//
// Recommended fields (browser-side):
// - v: 1
// - alg: "ECDH-P256+HKDF-SHA256+AES-256-GCM"
// - fingerprintSha256: matches workspace_encryption_keys.fingerprint
// - ephemeralPublicKeyJwk: public JWK for the ephemeral ECDH keypair used for this secret
// - ivB64: base64 iv (recommended 12 bytes)
// - ciphertextB64: base64 ciphertext (WebCrypto AES-GCM includes tag at end)
type SecretEnvelopeV1 struct {
	V                  int             `json:"v"`
	Alg                string          `json:"alg"`
	FingerprintSha256  string          `json:"fingerprintSha256"`
	EphemeralPublicJWK json.RawMessage `json:"ephemeralPublicKeyJwk"`
	IVB64              string          `json:"ivB64"`
	CiphertextB64      string          `json:"ciphertextB64"`
}

// encryptSecretJSON does NOT encrypt. It validates and returns the envelope bytes.
//
// This preserves the trust model:
// - plaintext encryption happens in the browser
// - backend only stores ciphertext + metadata needed for decryption on customer server
func (r *Repo) encryptSecretJSON(ctx context.Context, raw json.RawMessage, workspaceID uuid.UUID) ([]byte, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, ErrBadRequest
	}

	var env SecretEnvelopeV1
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, ErrBadRequest
	}

	// Basic envelope validation
	if env.V != 1 {
		return nil, ErrBadRequest
	}
	env.Alg = strings.TrimSpace(env.Alg)
	if env.Alg == "" {
		return nil, ErrBadRequest
	}
	env.FingerprintSha256 = strings.TrimSpace(env.FingerprintSha256)
	if env.FingerprintSha256 == "" {
		return nil, ErrBadRequest
	}
	if len(bytes.TrimSpace(env.EphemeralPublicJWK)) == 0 {
		return nil, ErrBadRequest
	}
	env.IVB64 = strings.TrimSpace(env.IVB64)
	env.CiphertextB64 = strings.TrimSpace(env.CiphertextB64)
	if env.IVB64 == "" || env.CiphertextB64 == "" {
		return nil, ErrBadRequest
	}

	// Validate base64 decode (and sanity check IV length)
	iv, err := base64.StdEncoding.DecodeString(env.IVB64)
	if err != nil || len(iv) == 0 {
		return nil, ErrBadRequest
	}
	// WebCrypto AES-GCM typically uses 12-byte IV; accept 12+ but reject tiny.
	if len(iv) < 12 {
		return nil, ErrBadRequest
	}

	ct, err := base64.StdEncoding.DecodeString(env.CiphertextB64)
	if err != nil || len(ct) == 0 {
		return nil, ErrBadRequest
	}

	// Ensure the workspace has an active encryption key and that the fingerprint matches.
	// This prevents storing envelopes that can't be decrypted with the current key.
	wsKey, err := r.GetWorkspaceEncryptionKey(ctx, workspaceID)
	if err != nil {
		// If not found / not set, secrets can't be stored
		return nil, err
	}
	if wsKey == nil || strings.TrimSpace(wsKey.Fingerprint) == "" {
		return nil, ErrBadRequest
	}
	if wsKey.Fingerprint != env.FingerprintSha256 {
		return nil, ErrBadRequest
	}

	// Store the envelope bytes exactly as provided (trimmed).
	// This is what the customer will later decrypt on their server.
	return raw, nil
}

// CountConfigKeysByProjectID returns the number of config keys in a project (excludes archived).
func (r *Repo) CountConfigKeysByProjectID(ctx context.Context, projectID uuid.UUID) (int, error) {
	const q = `SELECT COUNT(*) FROM config_keys WHERE project_id = $1 AND status != 'archived'`
	return r.scalarCount(ctx, q, projectID)
}
