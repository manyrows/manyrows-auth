-- +goose Up
-- Naver (nid.naver.com) sign-in: per-app toggle + OAuth2 client id/secret.
-- Naver is OAuth2-only (no OpenID Connect); the identity is read from Naver's
-- userinfo endpoint rather than a verified id_token, so this mirrors the
-- GitHub OAuth columns. Naver requires a client secret (it's mandatory on
-- their side, unlike Kakao's opt-in one).
--
-- All additive: apps default auth_method_naver=false, so the provider is off
-- on every app already in the wild until an admin configures it.
ALTER TABLE apps ADD COLUMN auth_method_naver boolean DEFAULT false NOT NULL;
ALTER TABLE apps ADD COLUMN naver_client_id text;
ALTER TABLE apps ADD COLUMN naver_client_secret_encrypted bytea;

-- +goose Down
ALTER TABLE apps DROP COLUMN IF EXISTS naver_client_secret_encrypted;
ALTER TABLE apps DROP COLUMN IF EXISTS naver_client_id;
ALTER TABLE apps DROP COLUMN IF EXISTS auth_method_naver;
