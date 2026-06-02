package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"manyrows-core/core"
	"manyrows-core/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

// ----------------------------
// User Fields (schema)
// ----------------------------

// User fields are pool-scoped post 00006: the schema lives on
// user_pools, values key on (user_id, user_field_id), and user_id
// already implies the pool. Two apps sharing a pool share these
// fields; isolated apps each have their own pool, so they each get
// their own schema, exactly as before.

const userFieldCols = `id, user_pool_id, key, value_type, visibility, user_editable, label, status, created_at, updated_at, created_by_account_id`

func scanUserField(row pgx.Row) (core.UserField, error) {
	var uf core.UserField
	var vt, vis string
	err := row.Scan(
		&uf.ID, &uf.UserPoolID, &uf.Key,
		&vt, &vis, &uf.UserEditable,
		&uf.Label, &uf.Status,
		&uf.CreatedAt, &uf.UpdatedAt, &uf.CreatedBy,
	)
	if err != nil {
		return core.UserField{}, err
	}
	uf.ValueType = core.UserFieldValueType(vt)
	uf.Visibility = vis
	return uf, nil
}

func (r *Repo) GetUserFieldsByUserPoolID(ctx context.Context, userPoolID uuid.UUID) ([]core.UserField, error) {
	q := fmt.Sprintf(`select %s from user_fields where user_pool_id = $1 order by created_at asc`, userFieldCols)

	rows, err := r.db.Pool().Query(ctx, q, userPoolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.UserField, 0, 16)
	for rows.Next() {
		var uf core.UserField
		var vt, vis string
		if err := rows.Scan(
			&uf.ID, &uf.UserPoolID, &uf.Key,
			&vt, &vis, &uf.UserEditable,
			&uf.Label, &uf.Status,
			&uf.CreatedAt, &uf.UpdatedAt, &uf.CreatedBy,
		); err != nil {
			return nil, err
		}
		uf.ValueType = core.UserFieldValueType(vt)
		uf.Visibility = vis
		out = append(out, uf)
	}
	return out, rows.Err()
}

func (r *Repo) CreateUserField(ctx context.Context, uf core.UserField) (core.UserField, error) {
	if uf.ID == uuid.Nil {
		uf.ID = utils.NewUUID()
	}

	q := fmt.Sprintf(`
		insert into user_fields (%s)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		returning %s
	`, userFieldCols, userFieldCols)

	row := r.db.Pool().QueryRow(ctx, q,
		uf.ID, uf.UserPoolID, uf.Key,
		string(uf.ValueType), uf.Visibility, uf.UserEditable,
		uf.Label, uf.Status,
		uf.CreatedAt, uf.UpdatedAt, uf.CreatedBy,
	)
	created, err := scanUserField(row)
	if err != nil {
		if IsUniqueViolation(err) {
			return core.UserField{}, ErrConflict
		}
		return core.UserField{}, err
	}
	return created, nil
}

func (r *Repo) GetUserFieldByID(ctx context.Context, userPoolID, fieldID uuid.UUID) (core.UserField, error) {
	q := fmt.Sprintf(`select %s from user_fields where id = $1 and user_pool_id = $2`, userFieldCols)
	row := r.db.Pool().QueryRow(ctx, q, fieldID, userPoolID)
	uf, err := scanUserField(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.UserField{}, ErrNotFound
		}
		return core.UserField{}, err
	}
	return uf, nil
}

func (r *Repo) GetUserFieldByUserPoolIDAndKey(ctx context.Context, userPoolID uuid.UUID, key string) (core.UserField, error) {
	q := fmt.Sprintf(`select %s from user_fields where user_pool_id = $1 and key = $2`, userFieldCols)
	row := r.db.Pool().QueryRow(ctx, q, userPoolID, key)
	uf, err := scanUserField(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.UserField{}, ErrNotFound
		}
		return core.UserField{}, err
	}
	return uf, nil
}

// UpdateUserField updates a user field definition using nil-based optional patches.
func (r *Repo) UpdateUserField(
	ctx context.Context,
	userPoolID, fieldID uuid.UUID,
	label *string, // nil=no change, non-nil=set value
	visibility *string,
	valueType *string,
	userEditable *bool,
	status *string,
) (core.UserField, error) {
	setParts := make([]string, 0, 6)
	args := make([]any, 0, 8)
	argN := 1

	if label != nil {
		setParts = append(setParts, fmt.Sprintf("label = $%d", argN))
		args = append(args, *label)
		argN++
	}
	if visibility != nil {
		setParts = append(setParts, fmt.Sprintf("visibility = $%d", argN))
		args = append(args, *visibility)
		argN++
	}
	if valueType != nil {
		setParts = append(setParts, fmt.Sprintf("value_type = $%d", argN))
		args = append(args, *valueType)
		argN++
	}
	if userEditable != nil {
		setParts = append(setParts, fmt.Sprintf("user_editable = $%d", argN))
		args = append(args, *userEditable)
		argN++
	}
	if status != nil {
		setParts = append(setParts, fmt.Sprintf("status = $%d", argN))
		args = append(args, *status)
		argN++
	}

	if len(setParts) == 0 {
		return r.GetUserFieldByID(ctx, userPoolID, fieldID)
	}

	setParts = append(setParts, "updated_at = now()")

	args = append(args, fieldID)
	whereID := argN
	argN++
	args = append(args, userPoolID)
	wherePool := argN

	q := fmt.Sprintf(`
		update user_fields set %s
		where id = $%d and user_pool_id = $%d
		returning %s
	`, strings.Join(setParts, ", "), whereID, wherePool, userFieldCols)

	row := r.db.Pool().QueryRow(ctx, q, args...)
	updated, err := scanUserField(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return core.UserField{}, ErrNotFound
		}
		if IsUniqueViolation(err) {
			return core.UserField{}, ErrConflict
		}
		return core.UserField{}, err
	}
	return updated, nil
}

func (r *Repo) DeleteUserField(ctx context.Context, userPoolID, fieldID uuid.UUID) error {
	const q = `delete from user_fields where id = $1 and user_pool_id = $2`
	tag, err := r.db.Pool().Exec(ctx, q, fieldID, userPoolID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Repo) CountUserFieldsByUserPoolID(ctx context.Context, userPoolID uuid.UUID) (int, error) {
	const q = `select count(*) from user_fields where user_pool_id = $1 and status <> 'archived'`
	return r.scalarCount(ctx, q, userPoolID)
}

// ----------------------------
// User Field Values
// ----------------------------

// GetUserFieldValuesByUser returns every value a user has. Pool scope
// is implicit through the user_id (a user lives in exactly one pool).
func (r *Repo) GetUserFieldValuesByUser(ctx context.Context, userID uuid.UUID) ([]core.UserFieldValue, error) {
	const q = `
		select id, user_id, user_field_id, value_json, updated_at, updated_by
		from user_field_values
		where user_id = $1
	`
	rows, err := r.db.Pool().Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.UserFieldValue, 0, 16)
	for rows.Next() {
		var v core.UserFieldValue
		if err := rows.Scan(&v.ID, &v.UserID, &v.UserFieldID, &v.ValueJSON, &v.UpdatedAt, &v.UpdatedBy); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *Repo) UpsertUserFieldValue(ctx context.Context, v core.UserFieldValue, valueJSON json.RawMessage) (core.UserFieldValue, error) {
	if v.ID == uuid.Nil {
		v.ID = utils.NewUUID()
	}

	const q = `
		insert into user_field_values (id, user_id, user_field_id, value_json, updated_at, updated_by)
		values ($1, $2, $3, $4, $5, $6)
		on conflict (user_id, user_field_id)
		do update set value_json = excluded.value_json, updated_at = excluded.updated_at, updated_by = excluded.updated_by
		returning id, user_id, user_field_id, value_json, updated_at, updated_by
	`

	var out core.UserFieldValue
	err := r.db.Pool().QueryRow(ctx, q,
		v.ID, v.UserID, v.UserFieldID,
		valueJSON, v.UpdatedAt, v.UpdatedBy,
	).Scan(&out.ID, &out.UserID, &out.UserFieldID, &out.ValueJSON, &out.UpdatedAt, &out.UpdatedBy)
	if err != nil {
		return core.UserFieldValue{}, err
	}
	return out, nil
}

func (r *Repo) DeleteUserFieldValue(ctx context.Context, fieldID, userID uuid.UUID) error {
	const q = `delete from user_field_values where user_field_id = $1 and user_id = $2`
	tag, err := r.db.Pool().Exec(ctx, q, fieldID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetClientUserFieldsForUser returns client-visible fields with their
// values for a user. The user's pool is looked up off the user row,
// so the schema picked matches the identity automatically.
func (r *Repo) GetClientUserFieldsForUser(ctx context.Context, userID uuid.UUID) ([]core.ClientUserFieldItem, error) {
	const q = `
		select uf.key, uf.value_type, uf.label, ufv.value_json
		from user_fields uf
		join users u on u.user_pool_id = uf.user_pool_id and u.id = $1
		left join user_field_values ufv on ufv.user_field_id = uf.id and ufv.user_id = u.id
		where uf.visibility = 'client'
		  and uf.status = 'active'
		order by uf.created_at asc
	`
	rows, err := r.db.Pool().Query(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]core.ClientUserFieldItem, 0, 16)
	for rows.Next() {
		var item core.ClientUserFieldItem
		var vt string
		var val *json.RawMessage
		if err := rows.Scan(&item.Key, &vt, &item.Label, &val); err != nil {
			return nil, err
		}
		item.Type = core.UserFieldValueType(vt)
		if val != nil {
			item.Value = *val
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
