-- +goose Up
-- Track when a server-to-server API key was last presented. Lets the admin
-- UI surface stale/unused keys and gives operators a coarse "is this key
-- still in use?" signal before rotating or deleting it. Nullable: a freshly
-- created key has never been used. Updated best-effort on each authenticated
-- request, so the value is approximate (we don't write on every call under
-- load) but monotonic.
ALTER TABLE api_keys ADD COLUMN last_used_at timestamp with time zone;

-- +goose Down
ALTER TABLE api_keys DROP COLUMN IF EXISTS last_used_at;
