package repo

import (
	"context"
	"time"

	"github.com/gofrs/uuid/v5"
)

type PromoteAppResult struct {
	ConfigValuesPromoted  int64 `json:"configValuesPromoted"`
	FlagOverridesPromoted int64 `json:"flagOverridesPromoted"`
}

// PromoteApp copies all config values and feature flag overrides from
// sourceAppID to targetAppID within the same project. Additive overwrite:
// source values overwrite target; target-only values are kept. Runs in a
// single transaction.
func (r *Repo) PromoteApp(
	ctx context.Context,
	projectID uuid.UUID,
	sourceAppID uuid.UUID,
	targetAppID uuid.UUID,
	actorAccountID uuid.UUID,
) (PromoteAppResult, error) {
	var result PromoteAppResult
	now := time.Now().UTC()

	tx, err := r.db.Pool().Begin(ctx)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const configQ = `
		INSERT INTO config_values (
			id, project_id, app_id, config_key_id,
			value_json, value_encrypted,
			updated_at, updated_by_account_id
		)
		SELECT
			gen_random_uuid(), cv.project_id, $3, cv.config_key_id,
			cv.value_json, cv.value_encrypted,
			$5, $4
		FROM config_values cv
		JOIN apps src ON src.id = $2 AND src.project_id = $1
		JOIN apps tgt ON tgt.id = $3 AND tgt.project_id = $1
		WHERE cv.app_id = $2
		  AND cv.project_id = $1
		ON CONFLICT (app_id, config_key_id)
		DO UPDATE SET
			value_json            = EXCLUDED.value_json,
			value_encrypted       = EXCLUDED.value_encrypted,
			updated_at            = EXCLUDED.updated_at,
			updated_by_account_id = EXCLUDED.updated_by_account_id
	`

	tag, err := tx.Exec(ctx, configQ, projectID, sourceAppID, targetAppID, actorAccountID, now)
	if err != nil {
		return result, err
	}
	result.ConfigValuesPromoted = tag.RowsAffected()

	const flagQ = `
		INSERT INTO feature_flag_overrides (
			id, project_id, app_id, feature_flag_id,
			enabled, status,
			updated_at, updated_by_account_id
		)
		SELECT
			gen_random_uuid(), ffe.project_id, $3, ffe.feature_flag_id,
			ffe.enabled, ffe.status,
			$5, $4
		FROM feature_flag_overrides ffe
		JOIN apps src ON src.id = $2 AND src.project_id = $1
		JOIN apps tgt ON tgt.id = $3 AND tgt.project_id = $1
		WHERE ffe.app_id = $2
		  AND ffe.project_id = $1
		ON CONFLICT (feature_flag_id, app_id)
		DO UPDATE SET
			enabled               = EXCLUDED.enabled,
			status                = EXCLUDED.status,
			updated_at            = EXCLUDED.updated_at,
			updated_by_account_id = EXCLUDED.updated_by_account_id
	`

	tag, err = tx.Exec(ctx, flagQ, projectID, sourceAppID, targetAppID, actorAccountID, now)
	if err != nil {
		return result, err
	}
	result.FlagOverridesPromoted = tag.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		return PromoteAppResult{}, err
	}

	return result, nil
}
