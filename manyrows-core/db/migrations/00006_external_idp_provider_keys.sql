-- +goose Up
-- Make room for the generic external-IdP provider key, "idp:<config-uuid>"
-- (see ExternalIDPProviderKey). Two existing constraints were sized only
-- for the four bespoke provider names and reject it:
--
--   1. user_identities.provider is varchar(20) — "idp:" + a 36-char UUID
--      is 40 chars. Widen it. Backward-compatible: short bespoke values
--      ("google", …) are unaffected and the unique indexes on
--      (provider, …) rebuild automatically.
--
--   2. oauth_states.provider has a CHECK allowlisting exactly
--      {google,apple,microsoft,github}. The generic authorize flow signs
--      state with provider "idp:<uuid>", which the allowlist rejects.
--      Broaden it to also accept the "idp:" namespace (still validates,
--      just no longer an exhaustive bespoke list).

ALTER TABLE user_identities ALTER COLUMN provider TYPE varchar(64);

ALTER TABLE oauth_states DROP CONSTRAINT IF EXISTS oauth_states_provider_check;
ALTER TABLE oauth_states ADD CONSTRAINT oauth_states_provider_check
    CHECK (provider = ANY (ARRAY['google'::text, 'apple'::text, 'microsoft'::text, 'github'::text]) OR provider LIKE 'idp:%');

-- +goose Down
-- Re-adding the narrow forms fails if any idp:* rows exist (they're
-- longer than 20 chars / outside the old allowlist); that's expected for
-- a down-migration after the feature has been used.
ALTER TABLE oauth_states DROP CONSTRAINT IF EXISTS oauth_states_provider_check;
ALTER TABLE oauth_states ADD CONSTRAINT oauth_states_provider_check
    CHECK (provider = ANY (ARRAY['google'::text, 'apple'::text, 'microsoft'::text, 'github'::text]));
ALTER TABLE user_identities ALTER COLUMN provider TYPE varchar(20);
