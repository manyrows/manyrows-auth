package repo

import "context"

// execAffectingOne runs an Exec on the pool that is expected to touch exactly
// one row, returning notFound when none matched and surfacing any other driver
// error unchanged. It collapses the repeated
// "Exec → check err → RowsAffected()==0 → ErrNotFound" block.
func (r *Repo) execAffectingOne(ctx context.Context, notFound error, q string, args ...any) error {
	ct, err := r.db.Pool().Exec(ctx, q, args...)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return notFound
	}
	return nil
}

// scalarCount runs a query expected to return a single integer (typically a
// count(*)) and returns it. It collapses the repeated
// "var n int; QueryRow(...).Scan(&n); return n" body.
func (r *Repo) scalarCount(ctx context.Context, q string, args ...any) (int, error) {
	var n int
	if err := r.db.Pool().QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = digits[i%10]
		i /= 10
	}
	return string(b[pos:])
}
