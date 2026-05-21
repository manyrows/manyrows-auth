-- +goose Up
-- QR cross-device sign-in: per-app enable toggle. Off-by-default so
-- existing installs don't suddenly expose a new sign-in surface
-- without an admin opting in. Matches the OIDC + passkey convention
-- of "new sign-in methods ship disabled."
--
-- All gating is at the handler layer (the /auth/pair/start entry
-- point + the hosted /qr-sign-in and /pair pages). Reads land on
-- the app row, which is already fetched on every per-app request.

ALTER TABLE apps ADD COLUMN qr_sign_in_enabled boolean DEFAULT false NOT NULL;

-- +goose Down
alter table if exists apps drop column if exists qr_sign_in_enabled;
