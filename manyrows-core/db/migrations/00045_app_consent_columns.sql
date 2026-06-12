-- +goose Up
-- Per-app legal-consent gating + a versioned, append-only acceptance record.
ALTER TABLE apps ADD COLUMN terms_url text NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN privacy_url text NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN consent_version text NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN require_consent boolean NOT NULL DEFAULT false;

CREATE TABLE user_consents (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    app_id uuid NOT NULL,
    kind text NOT NULL,
    version text NOT NULL,
    ip inet,
    user_agent text,
    accepted_at timestamp with time zone NOT NULL DEFAULT now()
);
ALTER TABLE ONLY user_consents ADD CONSTRAINT user_consents_pkey PRIMARY KEY (id);
ALTER TABLE ONLY user_consents ADD CONSTRAINT user_consents_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE ONLY user_consents ADD CONSTRAINT user_consents_app_id_fkey
    FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;
CREATE INDEX user_consents_user_app_idx ON user_consents (user_id, app_id);

-- +goose Down
DROP TABLE IF EXISTS user_consents;
ALTER TABLE apps DROP COLUMN IF EXISTS require_consent;
ALTER TABLE apps DROP COLUMN IF EXISTS consent_version;
ALTER TABLE apps DROP COLUMN IF EXISTS privacy_url;
ALTER TABLE apps DROP COLUMN IF EXISTS terms_url;
