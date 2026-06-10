-- +goose Up
-- Granted OIDC scope, persisted per refresh-token chain (per-GRANT — one
-- session can hold grants for multiple OIDC clients). '' = first-party /
-- pre-feature chains. Inherited by replacement rows on rotation.
ALTER TABLE client_refresh_tokens ADD COLUMN oidc_scope text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE client_refresh_tokens DROP COLUMN IF EXISTS oidc_scope;
