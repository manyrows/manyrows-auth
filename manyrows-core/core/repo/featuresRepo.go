package repo

import (
	"context"
	"errors"
	"fmt"

	"manyrows-core/core"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ----------------------
// Feature Flags (project)
// ----------------------

func (r *Repo) GetFeatureFlagsByProjectID(ctx context.Context, projectID uuid.UUID) ([]core.FeatureFlag, error) {
	const q = `
		select
			id,
			project_id,
			key,
			description,
			scope,
			default_enabled,
			status,
			created_at,
			updated_at,
			created_by_account_id
		from feature_flags
		where project_id = $1
		order by created_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.FeatureFlag
	for rows.Next() {
		var ff core.FeatureFlag
		var desc *string
		var scope string
		if err := rows.Scan(
			&ff.ID,
			&ff.ProjectID,
			&ff.Key,
			&desc,
			&scope,
			&ff.DefaultEnabled,
			&ff.Status,
			&ff.CreatedAt,
			&ff.UpdatedAt,
			&ff.CreatedBy,
		); err != nil {
			return nil, err
		}
		ff.Description = desc
		ff.Scope = core.FeatureFlagScope(scope)
		out = append(out, ff)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) GetFeatureFlagByID(ctx context.Context, projectID uuid.UUID, featureFlagID uuid.UUID) (core.FeatureFlag, error) {
	const q = `
		select
			id,
			project_id,
			key,
			description,
			scope,
			default_enabled,
			status,
			created_at,
			updated_at,
			created_by_account_id
		from feature_flags
		where project_id = $1 and id = $2
	`

	var ff core.FeatureFlag
	var desc *string
	var scope string
	err := r.db.Pool().QueryRow(ctx, q, projectID, featureFlagID).Scan(
		&ff.ID,
		&ff.ProjectID,
		&ff.Key,
		&desc,
		&scope,
		&ff.DefaultEnabled,
		&ff.Status,
		&ff.CreatedAt,
		&ff.UpdatedAt,
		&ff.CreatedBy,
	)
	if err != nil {
		if isNoRows(err) {
			return core.FeatureFlag{}, ErrNotFound
		}
		return core.FeatureFlag{}, err
	}
	ff.Description = desc
	ff.Scope = core.FeatureFlagScope(scope)
	return ff, nil
}

func (r *Repo) GetFeatureFlagByProjectIDAndKey(ctx context.Context, projectID uuid.UUID, key string) (core.FeatureFlag, error) {
	const q = `
		select
			id,
			project_id,
			key,
			description,
			scope,
			default_enabled,
			status,
			created_at,
			updated_at,
			created_by_account_id
		from feature_flags
		where project_id = $1 and key = $2 and status = 'active'
	`

	var ff core.FeatureFlag
	var desc *string
	var scope string
	err := r.db.Pool().QueryRow(ctx, q, projectID, key).Scan(
		&ff.ID,
		&ff.ProjectID,
		&ff.Key,
		&desc,
		&scope,
		&ff.DefaultEnabled,
		&ff.Status,
		&ff.CreatedAt,
		&ff.UpdatedAt,
		&ff.CreatedBy,
	)
	if err != nil {
		if isNoRows(err) {
			return core.FeatureFlag{}, ErrNotFound
		}
		return core.FeatureFlag{}, err
	}
	ff.Description = desc
	ff.Scope = core.FeatureFlagScope(scope)
	return ff, nil
}

func (r *Repo) CreateFeatureFlag(ctx context.Context, ff core.FeatureFlag) (core.FeatureFlag, error) {
	const q = `
		insert into feature_flags (
			id,
			project_id,
			key,
			description,
			scope,
			default_enabled,
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
			scope,
			default_enabled,
			status,
			created_at,
			updated_at,
			created_by_account_id
	`

	var out core.FeatureFlag
	var desc *string
	var scope string
	err := r.db.Pool().QueryRow(
		ctx,
		q,
		ff.ID,
		ff.ProjectID,
		ff.Key,
		ff.Description,
		string(ff.Scope),
		ff.DefaultEnabled,
		ff.Status,
		ff.CreatedAt,
		ff.UpdatedAt,
		ff.CreatedBy,
	).Scan(
		&out.ID,
		&out.ProjectID,
		&out.Key,
		&desc,
		&scope,
		&out.DefaultEnabled,
		&out.Status,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.CreatedBy,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return core.FeatureFlag{}, ErrConflict
		}
		return core.FeatureFlag{}, err
	}
	out.Description = desc
	out.Scope = core.FeatureFlagScope(scope)
	return out, nil
}

// UpdateFeatureFlag updates only fields that are non-nil.
// Description behavior:
//   - description == nil: no change
//   - *description == "": set NULL
//   - otherwise: set to provided string
func (r *Repo) UpdateFeatureFlag(
	ctx context.Context,
	projectID uuid.UUID,
	featureFlagID uuid.UUID,
	description *string,
	scope *core.FeatureFlagScope,
	defaultEnabled *bool,
	status *string,
) (core.FeatureFlag, error) {
	sets := make([]string, 0, 5)
	args := make([]any, 0, 8)

	// where args first
	args = append(args, projectID)     // $1
	args = append(args, featureFlagID) // $2
	argN := 3

	if description != nil {
		sets = append(sets, fmt.Sprintf(`description = $%d`, argN))
		if *description == "" {
			args = append(args, nil) // NULL
		} else {
			args = append(args, *description)
		}
		argN++
	}

	if scope != nil {
		sets = append(sets, fmt.Sprintf(`scope = $%d`, argN))
		args = append(args, string(*scope))
		argN++
	}

	if defaultEnabled != nil {
		sets = append(sets, fmt.Sprintf(`default_enabled = $%d`, argN))
		args = append(args, *defaultEnabled)
		argN++
	}

	if status != nil {
		sets = append(sets, fmt.Sprintf(`status = $%d`, argN))
		args = append(args, *status)
		argN++
	}

	if len(sets) == 0 {
		return r.GetFeatureFlagByID(ctx, projectID, featureFlagID)
	}

	// always touch updated_at
	sets = append(sets, `updated_at = now()`)

	q := fmt.Sprintf(`
		update feature_flags
		set %s
		where project_id = $1 and id = $2
		returning
			id,
			project_id,
			key,
			description,
			scope,
			default_enabled,
			status,
			created_at,
			updated_at,
			created_by_account_id
	`, joinSQL(sets, ", "))

	var out core.FeatureFlag
	var desc *string
	var scopeOut string
	err := r.db.Pool().QueryRow(ctx, q, args...).Scan(
		&out.ID,
		&out.ProjectID,
		&out.Key,
		&desc,
		&scopeOut,
		&out.DefaultEnabled,
		&out.Status,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.CreatedBy,
	)
	if err != nil {
		if isNoRows(err) {
			return core.FeatureFlag{}, ErrNotFound
		}
		if IsUniqueViolation(err) {
			return core.FeatureFlag{}, ErrConflict
		}
		return core.FeatureFlag{}, err
	}
	out.Description = desc
	out.Scope = core.FeatureFlagScope(scopeOut)
	return out, nil
}

func (r *Repo) DeleteFeatureFlag(ctx context.Context, projectID uuid.UUID, featureFlagID uuid.UUID) error {
	const q = `
		delete from feature_flags
		where project_id = $1 and id = $2
	`
	return r.execAffectingOne(ctx, ErrNotFound, q, projectID, featureFlagID)
}

// --------------------------------------
// Feature Flag Per-App Overrides (UI)
// --------------------------------------

func (r *Repo) GetFeatureFlagOverridesByProjectID(ctx context.Context, projectID uuid.UUID) ([]core.FeatureFlagOverride, error) {
	const q = `
		select
			id,
			project_id,
			app_id,
			feature_flag_id,
			enabled,
			role_ids,
			status,
			updated_at,
			updated_by_account_id
		from feature_flag_overrides
		where project_id = $1
		order by updated_at desc
	`

	rows, err := r.db.Pool().Query(ctx, q, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.FeatureFlagOverride
	for rows.Next() {
		var o core.FeatureFlagOverride
		if err := rows.Scan(
			&o.ID,
			&o.ProjectID,
			&o.AppID,
			&o.FeatureFlagID,
			&o.Enabled,
			&o.RoleIDs,
			&o.Status,
			&o.UpdatedAt,
			&o.UpdatedBy,
		); err != nil {
			return nil, err
		}
		out = append(out, o)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetFeatureFlagOverride returns the single override row for (project, flag, env).
func (r *Repo) GetFeatureFlagOverride(
	ctx context.Context,
	projectID uuid.UUID,
	featureFlagID uuid.UUID,
	appID uuid.UUID,
) (*core.FeatureFlagOverride, error) {
	const q = `
		select
			id,
			project_id,
			app_id,
			feature_flag_id,
			enabled,
			role_ids,
			status,
			updated_at,
			updated_by_account_id
		from feature_flag_overrides
		where project_id = $1
		  and feature_flag_id = $2
		  and app_id = $3
		limit 1
	`

	var out core.FeatureFlagOverride
	err := r.db.Pool().QueryRow(ctx, q, projectID, featureFlagID, appID).Scan(
		&out.ID,
		&out.ProjectID,
		&out.AppID,
		&out.FeatureFlagID,
		&out.Enabled,
		&out.RoleIDs,
		&out.Status,
		&out.UpdatedAt,
		&out.UpdatedBy,
	)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &out, nil
}

func (r *Repo) UpsertFeatureFlagOverride(ctx context.Context, o core.FeatureFlagOverride) (core.FeatureFlagOverride, error) {
	// Ensure feature flag belongs to project
	{
		const q = `select 1 from feature_flags where id = $1 and project_id = $2`
		var one int
		err := r.db.Pool().QueryRow(ctx, q, o.FeatureFlagID, o.ProjectID).Scan(&one)
		if err != nil {
			if isNoRows(err) {
				return core.FeatureFlagOverride{}, ErrNotFound
			}
			return core.FeatureFlagOverride{}, err
		}
	}

	// Ensure app belongs to project
	{
		const q = `select 1 from apps where id = $1 and project_id = $2`
		var one int
		err := r.db.Pool().QueryRow(ctx, q, o.AppID, o.ProjectID).Scan(&one)
		if err != nil {
			if isNoRows(err) {
				return core.FeatureFlagOverride{}, ErrNotFound
			}
			return core.FeatureFlagOverride{}, err
		}
	}

	// Upsert by unique(feature_flag_id, app_id)
	const q = `
		insert into feature_flag_overrides (
			id,
			project_id,
			app_id,
			feature_flag_id,
			enabled,
			role_ids,
			status,
			updated_at,
			updated_by_account_id
		) values (
			$1,$2,$3,$4,$5,$6,$7,$8,$9
		)
		on conflict (feature_flag_id, app_id)
		do update set
			enabled = excluded.enabled,
			role_ids = excluded.role_ids,
			status = excluded.status,
			updated_at = excluded.updated_at,
			updated_by_account_id = excluded.updated_by_account_id
		returning
			id,
			project_id,
			app_id,
			feature_flag_id,
			enabled,
			role_ids,
			status,
			updated_at,
			updated_by_account_id
	`

	if o.RoleIDs == nil {
		o.RoleIDs = []uuid.UUID{}
	}

	var out core.FeatureFlagOverride
	err := r.db.Pool().QueryRow(
		ctx,
		q,
		o.ID,
		o.ProjectID,
		o.AppID,
		o.FeatureFlagID,
		o.Enabled,
		o.RoleIDs,
		o.Status,
		o.UpdatedAt,
		o.UpdatedBy,
	).Scan(
		&out.ID,
		&out.ProjectID,
		&out.AppID,
		&out.FeatureFlagID,
		&out.Enabled,
		&out.RoleIDs,
		&out.Status,
		&out.UpdatedAt,
		&out.UpdatedBy,
	)
	if err != nil {
		if IsUniqueViolation(err) {
			return core.FeatureFlagOverride{}, ErrConflict
		}
		return core.FeatureFlagOverride{}, err
	}
	return out, nil
}

func (r *Repo) DeleteFeatureFlagOverride(ctx context.Context, projectID uuid.UUID, featureFlagID uuid.UUID, appID uuid.UUID) error {
	const q = `
		delete from feature_flag_overrides
		where project_id = $1 and feature_flag_id = $2 and app_id = $3
	`
	return r.execAffectingOne(ctx, ErrNotFound, q, projectID, featureFlagID, appID)
}

// ----------------------
// helpers (repo-local)
// ----------------------

func isNoRows(err error) bool {
	return err != nil && errors.Is(err, pgx.ErrNoRows)
}

func joinSQL(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += sep + parts[i]
	}
	return out
}

// GetEvaluatedFeatureFlagsForProjectAndApp returns feature flags for a project
// evaluated for a specific app.
//
// Rules:
// - If a per-app override exists, use feature_flag_overrides.enabled.
// - Otherwise, fall back to feature_flags.default_enabled.
// - Flags must belong to the given project.
func (r *Repo) GetEvaluatedFeatureFlagsForProjectAndApp(
	ctx context.Context,
	projectID uuid.UUID,
	appID uuid.UUID,
) ([]core.EvaluatedFeatureFlag, error) {
	const q = `
select
  ff.key,
  coalesce(ffe.enabled, ff.default_enabled) as enabled,
  coalesce(ffe.role_ids, '{}') as role_ids
from feature_flags ff
left join feature_flag_overrides ffe
  on ffe.project_id = ff.project_id
 and ffe.feature_flag_id = ff.id
 and ffe.app_id = $2
where ff.project_id = $1
order by ff.key asc;
`

	rows, err := r.db.Pool().Query(ctx, q, projectID, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.EvaluatedFeatureFlag, 0, 32)
	for rows.Next() {
		var f core.EvaluatedFeatureFlag
		if err := rows.Scan(&f.Key, &f.Enabled, &f.RoleIDs); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

// CountFeatureFlagsByProjectID returns the number of feature flags in a project (excludes archived).
func (r *Repo) CountFeatureFlagsByProjectID(ctx context.Context, projectID uuid.UUID) (int, error) {
	const q = `SELECT COUNT(*) FROM feature_flags WHERE project_id = $1 AND status != 'archived'`
	return r.scalarCount(ctx, q, projectID)
}
