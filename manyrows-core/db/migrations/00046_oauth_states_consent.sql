-- +goose Up
ALTER TABLE oauth_states ADD COLUMN consent_accepted boolean NOT NULL DEFAULT false;
ALTER TABLE oauth_states ADD COLUMN consent_version text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE oauth_states DROP COLUMN IF EXISTS consent_version;
ALTER TABLE oauth_states DROP COLUMN IF EXISTS consent_accepted;