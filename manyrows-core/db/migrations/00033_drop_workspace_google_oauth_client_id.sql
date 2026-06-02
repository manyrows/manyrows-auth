-- +goose Up
-- Drop the vestigial workspaces.google_oauth_client_id column. It was never
-- written with a real value (the first-boot workspace is created without it
-- and the workspace update handler only touches name/slug) and never read for
-- auth: every Google OAuth flow uses the per-app apps.google_oauth_client_id
-- instead. The squashed baseline (00001) no longer creates it, so IF EXISTS
-- makes this a no-op on freshly built databases and a real drop on older ones.
ALTER TABLE workspaces DROP COLUMN IF EXISTS google_oauth_client_id;

-- +goose Down
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS google_oauth_client_id text;
