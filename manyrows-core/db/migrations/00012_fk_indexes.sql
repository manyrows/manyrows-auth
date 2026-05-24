-- +goose Up
-- Index foreign-key columns that currently have no covering index, so reverse
-- lookups and ON DELETE cascade/SET NULL don't sequential-scan the child table.
--
-- Each column below backs a FK whose existing indexes (if any) lead with a
-- different column, so Postgres can't use them for the FK direction:
--   - user_permissions.permission_id      (composite ux_ leads with app_id)
--   - email_change_requests.app_id        (only user_id is indexed)
--   - webauthn_challenges.app_id/user_id  (only expires_at is indexed)
--   - the account-audit FKs (created_by / invited_by / *_by_account_id) which
--     are scanned when an account is deleted.
--
-- Unqualified names on purpose: these must land in the `manyrows` schema.
-- IF NOT EXISTS keeps the migration idempotent.
CREATE INDEX IF NOT EXISTS idx_user_permissions_permission ON user_permissions USING btree (permission_id);
CREATE INDEX IF NOT EXISTS idx_email_change_requests_app ON email_change_requests USING btree (app_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_app ON webauthn_challenges USING btree (app_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges USING btree (user_id);
CREATE INDEX IF NOT EXISTS idx_config_keys_created_by_account ON config_keys USING btree (created_by_account_id);
CREATE INDEX IF NOT EXISTS idx_config_values_updated_by_account ON config_values USING btree (updated_by_account_id);
CREATE INDEX IF NOT EXISTS idx_team_invites_invited_by ON team_invites USING btree (invited_by);
CREATE INDEX IF NOT EXISTS idx_products_created_by_account ON products USING btree (created_by_account_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_created_by ON webhooks USING btree (created_by);
CREATE INDEX IF NOT EXISTS idx_workspace_encryption_keys_created_by ON workspace_encryption_keys USING btree (created_by);

-- +goose Down
DROP INDEX IF EXISTS idx_user_permissions_permission;
DROP INDEX IF EXISTS idx_email_change_requests_app;
DROP INDEX IF EXISTS idx_webauthn_challenges_app;
DROP INDEX IF EXISTS idx_webauthn_challenges_user;
DROP INDEX IF EXISTS idx_config_keys_created_by_account;
DROP INDEX IF EXISTS idx_config_values_updated_by_account;
DROP INDEX IF EXISTS idx_team_invites_invited_by;
DROP INDEX IF EXISTS idx_products_created_by_account;
DROP INDEX IF EXISTS idx_webhooks_created_by;
DROP INDEX IF EXISTS idx_workspace_encryption_keys_created_by;
