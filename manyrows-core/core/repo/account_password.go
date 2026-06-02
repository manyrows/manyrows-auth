package repo

import (
	"context"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/jackc/pgx/v5"
)

func (r *Repo) UpdateAccountPasswordTx(ctx context.Context, tx pgx.Tx, accountID uuid.UUID, passwordHash string, passwordSetAt time.Time) error {
	const q = `
update accounts
set
  password_hash = $2,
  password_set_at = $3
where id = $1;
`
	tag, err := tx.Exec(ctx, q, accountID, passwordHash, passwordSetAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
