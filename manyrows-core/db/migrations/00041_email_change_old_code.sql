-- +goose Up
-- Old-address confirmation for email changes: the request now carries a
-- second code hash, emailed to the user's CURRENT address. Both codes must
-- verify before the change applies. Default '' (never verifies) so pending
-- rows from before the deploy fail closed and get re-requested (15m TTL).
ALTER TABLE email_change_requests ADD COLUMN old_code_hash text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE email_change_requests DROP COLUMN IF EXISTS old_code_hash;
