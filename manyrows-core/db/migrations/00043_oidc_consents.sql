-- +goose Up
-- Remembered OIDC consent per user per app (the OIDC client is 1:1 with
-- the app). scope holds the CUMULATIVE union of granted scope sets; a
-- request needing more than the remembered set re-prompts and the union
-- is stored. Gated by apps.oidc_require_consent (default off — many RPs
-- are first-party since client==app); prompt=consent forces the screen
-- regardless.
CREATE TABLE oidc_consents (
    user_id uuid NOT NULL,
    app_id uuid NOT NULL,
    scope text NOT NULL,
    granted_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE ONLY oidc_consents
    ADD CONSTRAINT oidc_consents_pkey PRIMARY KEY (user_id, app_id);

ALTER TABLE ONLY oidc_consents
    ADD CONSTRAINT oidc_consents_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE ONLY oidc_consents
    ADD CONSTRAINT oidc_consents_app_id_fkey FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE apps ADD COLUMN oidc_require_consent boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE apps DROP COLUMN IF EXISTS oidc_require_consent;
DROP TABLE IF EXISTS oidc_consents;
