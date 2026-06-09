package repo

import (
	"context"

	"manyrows-core/core"
)

// DisableAccountTOTPByEmail clears the TOTP enrolment (secret, enabled
// timestamp, and backup codes) for the admin account with the given email,
// matched case-insensitively. It is the out-of-band recovery used by the
// `reset-admin-2fa` CLI command for an operator locked out of the console
// when no other owner is available to reset it. Returns
// core.ErrAccountNotFound when no account matches.
func (r *Repo) DisableAccountTOTPByEmail(ctx context.Context, email string) error {
	const q = `
update accounts
set totp_secret_encrypted = null,
    totp_enabled_at = null,
    totp_backup_codes_encrypted = null
where lower(email) = lower($1);
`
	return r.execAffectingOne(ctx, core.ErrAccountNotFound, q, email)
}
