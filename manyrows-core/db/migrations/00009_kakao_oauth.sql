-- +goose Up
-- Kakao (kauth.kakao.com) sign-in: per-app toggle + REST API key (the
-- client_id) + encrypted client secret. Mirrors the Google/Microsoft OAuth
-- columns exactly. Like Microsoft, Kakao is OIDC and the id_token is verified
-- locally against Kakao's JWKS; unlike Google there's no tokeninfo endpoint.
--
-- All additive: apps default auth_method_kakao=false, so the provider is off
-- on every app already in the wild until an admin configures it.
ALTER TABLE apps ADD COLUMN auth_method_kakao boolean DEFAULT false NOT NULL;
ALTER TABLE apps ADD COLUMN kakao_client_id text;
ALTER TABLE apps ADD COLUMN kakao_client_secret_encrypted bytea;

-- +goose Down
ALTER TABLE apps DROP COLUMN IF EXISTS kakao_client_secret_encrypted;
ALTER TABLE apps DROP COLUMN IF EXISTS kakao_client_id;
ALTER TABLE apps DROP COLUMN IF EXISTS auth_method_kakao;
