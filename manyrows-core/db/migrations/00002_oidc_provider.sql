-- +goose Up
-- OIDC provider surface. Adds the short-lived authorization-code table,
-- the pending-authorize table (carries the original /authorize request
-- across the AppKit sign-in round-trip), and the per-app OIDC config
-- columns on apps.
--
-- All additive: existing customer / SDK flows are untouched. Apps stay
-- oidc_enabled=false until an admin flips the toggle, so the new
-- endpoints 404 by default on every app already in the wild.

CREATE TABLE oidc_auth_codes (
    code_hash text NOT NULL,
    app_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid,
    nonce text,
    redirect_uri text NOT NULL,
    scope text NOT NULL,
    code_challenge text NOT NULL,
    code_challenge_method text DEFAULT 'S256'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    CONSTRAINT oidc_auth_codes_code_challenge_method_check CHECK ((code_challenge_method = 'S256'::text)),
    CONSTRAINT oidc_auth_codes_expires_after_create CHECK ((expires_at > created_at))
);

CREATE TABLE oidc_pending_authorize (
    id uuid NOT NULL,
    app_id uuid NOT NULL,
    request_params jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    CONSTRAINT oidc_pending_authorize_expires_after_create CHECK ((expires_at > created_at))
);

ALTER TABLE apps ADD COLUMN oidc_enabled boolean DEFAULT false NOT NULL;
ALTER TABLE apps ADD COLUMN oidc_client_secret_hash text;
ALTER TABLE apps ADD COLUMN oidc_redirect_uris text[] DEFAULT '{}'::text[] NOT NULL;
ALTER TABLE apps ADD COLUMN oidc_post_logout_redirect_uris text[] DEFAULT '{}'::text[] NOT NULL;

ALTER TABLE ONLY oidc_auth_codes
    ADD CONSTRAINT oidc_auth_codes_pkey PRIMARY KEY (code_hash);

ALTER TABLE ONLY oidc_pending_authorize
    ADD CONSTRAINT oidc_pending_authorize_pkey PRIMARY KEY (id);

ALTER TABLE ONLY oidc_auth_codes
    ADD CONSTRAINT oidc_auth_codes_app_id_fkey FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE ONLY oidc_auth_codes
    ADD CONSTRAINT oidc_auth_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE ONLY oidc_auth_codes
    ADD CONSTRAINT oidc_auth_codes_session_id_fkey FOREIGN KEY (session_id) REFERENCES client_sessions(id) ON DELETE SET NULL;

ALTER TABLE ONLY oidc_pending_authorize
    ADD CONSTRAINT oidc_pending_authorize_app_id_fkey FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

-- Janitor sweep index (cheap "delete where expires_at < now()" scans).
CREATE INDEX idx_oidc_auth_codes_expires ON oidc_auth_codes USING btree (expires_at);
CREATE INDEX idx_oidc_pending_authorize_expires ON oidc_pending_authorize USING btree (expires_at);

-- Partial index: unused codes lookup during /token exchange. Codes are
-- short-lived and used-or-expired rows trail off quickly, so the partial
-- form keeps the working set tiny.
CREATE INDEX idx_oidc_auth_codes_unused ON oidc_auth_codes USING btree (code_hash) WHERE (used_at IS NULL);

-- +goose Down
alter table if exists apps drop column if exists oidc_post_logout_redirect_uris;
alter table if exists apps drop column if exists oidc_redirect_uris;
alter table if exists apps drop column if exists oidc_client_secret_hash;
alter table if exists apps drop column if exists oidc_enabled;
drop table if exists oidc_pending_authorize cascade;
drop table if exists oidc_auth_codes cascade;
