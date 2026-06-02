-- +goose Up
-- Generic external identity providers (the OAuth/OIDC *client* side:
-- ManyRows signing users in via someone else's IdP). Distinct from the
-- oidc_* tables added in 00002, which are the *provider* side (ManyRows
-- acting as an IdP that downstream apps consume).
--
-- One row per configured external IdP per app — a one-to-many config,
-- unlike the bespoke Google/Apple/Microsoft/GitHub providers which are
-- singleton boolean flags on `apps`. An app can wire several at once
-- (e.g. a corporate Okta AND Discord).
--
-- Two modes:
--   'oidc'   — discover endpoints from issuer_url's
--              /.well-known/openid-configuration, verify a signed
--              id_token via the provider's JWKS. (Okta, Auth0, Keycloak,
--              Entra, GitLab, ...)  Generalizes Google/Microsoft/Apple.
--   'oauth2' — no discovery, no id_token; explicit endpoints, identity
--              read from the userinfo endpoint over TLS. (Discord,
--              Twitch, bare OAuth2.)  Generalizes the GitHub posture.
--
-- All additive. No existing flow references this table; bespoke
-- providers are untouched.

CREATE TABLE external_idps (
    id uuid NOT NULL,
    app_id uuid NOT NULL,

    -- Stable per-app key. Used as the URL route segment
    -- (/auth/idp/<slug>/...) and the AppKit button identity. NOTE: the
    -- identity provider-key in user_identities.provider is keyed by this
    -- row's UUID ("idp:<id>"), NOT the slug — identities are matched
    -- pool-wide and slugs are only unique per-app, so a slug-based key
    -- could collide across apps that share a pool. See ExternalIDPProviderKey.
    slug text NOT NULL,
    display_name text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,

    mode text DEFAULT 'oidc' NOT NULL,

    -- OIDC mode discovers from issuer_url; the explicit endpoint columns
    -- are the OAuth2-mode source (and an optional OIDC manual override).
    issuer_url text,
    authorize_url text,
    token_url text,
    userinfo_url text,
    jwks_url text,

    client_id text NOT NULL,
    -- AAD-scoped ciphertext, same scheme as the bespoke providers'
    -- *_client_secret_encrypted columns (crypto.AAD("external_idps",
    -- "client_secret_encrypted", id)).
    client_secret_encrypted bytea NOT NULL,

    scopes text DEFAULT 'openid email profile' NOT NULL,

    -- Claim/field mapping. Defaults are the OIDC standard claims; for
    -- oauth2 mode these name fields in the userinfo JSON instead.
    subject_field text DEFAULT 'sub' NOT NULL,
    email_field text DEFAULT 'email' NOT NULL,
    email_verified_field text,
    name_field text,

    -- Optional AppKit button icon (FontAwesome name); display_name is
    -- the label.
    button_icon text,

    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,

    CONSTRAINT external_idps_mode_check CHECK (mode IN ('oidc', 'oauth2')),
    -- Lowercase DNS-label-ish slug: safe in URLs, route segments, and
    -- the "oidc:<slug>" identity key.
    CONSTRAINT external_idps_slug_format CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    -- OIDC needs an issuer to discover from; OAuth2 needs the explicit
    -- authorize+token endpoints. Enforced here so a misconfigured row
    -- can't reach the handler.
    CONSTRAINT external_idps_endpoints_per_mode CHECK (
        (mode = 'oidc'   AND issuer_url IS NOT NULL)
        OR
        (mode = 'oauth2' AND authorize_url IS NOT NULL AND token_url IS NOT NULL AND userinfo_url IS NOT NULL)
    )
);

ALTER TABLE ONLY external_idps
    ADD CONSTRAINT external_idps_pkey PRIMARY KEY (id);

-- One provider per (app, slug). Leading app_id also serves the
-- "list every IdP for this app" query, so no separate app_id index.
CREATE UNIQUE INDEX external_idps_app_slug_uniq ON external_idps USING btree (app_id, slug);

ALTER TABLE ONLY external_idps
    ADD CONSTRAINT external_idps_app_id_fkey FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

-- +goose Down
drop table if exists external_idps cascade;
