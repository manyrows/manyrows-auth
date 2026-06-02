-- +goose Up
-- Allow Kakao and Naver sign-in to create OAuth states.
--
-- Kakao/Naver insert oauth_states rows with provider 'kakao' / 'naver', but
-- oauth_states_provider_check (last set in 00006) only allowlists
-- google/apple/microsoft/github plus external IdPs (idp:%). The 00009/00010
-- provider migrations added the apps columns but missed broadening this CHECK,
-- so every Kakao/Naver popup fails at state creation with a 23514. Add both.
--
-- oauth_states is transient (short TTL + janitor sweep), so no existing row can
-- violate the wider constraint; the DROP/ADD is safe.
ALTER TABLE oauth_states DROP CONSTRAINT IF EXISTS oauth_states_provider_check;
ALTER TABLE oauth_states ADD CONSTRAINT oauth_states_provider_check
    CHECK (provider = ANY (ARRAY['google'::text, 'apple'::text, 'microsoft'::text, 'github'::text, 'kakao'::text, 'naver'::text]) OR provider LIKE 'idp:%');

-- +goose Down
ALTER TABLE oauth_states DROP CONSTRAINT IF EXISTS oauth_states_provider_check;
ALTER TABLE oauth_states ADD CONSTRAINT oauth_states_provider_check
    CHECK (provider = ANY (ARRAY['google'::text, 'apple'::text, 'microsoft'::text, 'github'::text]) OR provider LIKE 'idp:%');
