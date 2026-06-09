-- +goose Up
-- Least-privilege + blast-radius controls for server-API keys.
--   scope: 'read' keys may only perform GET/HEAD on the server API;
--          'read_write' (the DEFAULT, so existing keys keep full access) may
--          do anything. Enforced in apiKeyMiddleware.
--   expires_at: optional hard expiry; the auth middleware rejects keys past it.
--               NULL means the key never expires.
ALTER TABLE api_keys ADD COLUMN scope text NOT NULL DEFAULT 'read_write';
ALTER TABLE api_keys ADD CONSTRAINT api_keys_scope_check CHECK (scope IN ('read', 'read_write'));
ALTER TABLE api_keys ADD COLUMN expires_at timestamp with time zone;

-- +goose Down
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_scope_check;
ALTER TABLE api_keys DROP COLUMN IF EXISTS scope;
ALTER TABLE api_keys DROP COLUMN IF EXISTS expires_at;
