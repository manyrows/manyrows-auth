-- +goose Up
-- Organizations: multi-tenant orgs for an app's end-users. Scoped to an app
-- (orgs are runtime tenant data, per-environment). Opt-in per app via
-- apps.organizations_enabled. Identity still lives at the pool; orgs only
-- partition usage of an app. See docs/superpowers/specs/2026-06-05-organizations-design.md.

ALTER TABLE apps ADD COLUMN organizations_enabled boolean DEFAULT false NOT NULL;
ALTER TABLE apps ADD COLUMN org_creation_policy text DEFAULT 'invite_only' NOT NULL;
ALTER TABLE apps
    ADD CONSTRAINT apps_org_creation_policy_check
    CHECK (org_creation_policy = ANY (ARRAY['self_serve'::text, 'invite_only'::text, 'admin_only'::text]));

CREATE TABLE organizations (
    id uuid NOT NULL,
    app_id uuid NOT NULL,
    name text NOT NULL,
    slug text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organizations_status_check CHECK ((status = ANY (ARRAY['active'::text, 'archived'::text])))
);

CREATE TABLE organization_members (
    id uuid NOT NULL,
    org_id uuid NOT NULL,
    user_id uuid NOT NULL,
    org_role text DEFAULT 'member'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    joined_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_members_org_role_check CHECK ((org_role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text]))),
    CONSTRAINT organization_members_status_check CHECK ((status = ANY (ARRAY['active'::text, 'pending'::text, 'disabled'::text])))
);

CREATE TABLE organization_member_roles (
    id uuid NOT NULL,
    member_id uuid NOT NULL,
    role_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE organization_invites (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    email text NOT NULL,
    org_role text DEFAULT 'member'::text NOT NULL,
    role_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    invited_by uuid,
    token_hash text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    accepted_at timestamp with time zone,
    CONSTRAINT organization_invites_org_role_check CHECK ((org_role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text]))),
    CONSTRAINT organization_invites_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'accepted'::text, 'revoked'::text, 'expired'::text])))
);

ALTER TABLE client_sessions ADD COLUMN organization_id uuid;

ALTER TABLE ONLY organizations ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);
ALTER TABLE ONLY organization_members ADD CONSTRAINT organization_members_pkey PRIMARY KEY (id);
ALTER TABLE ONLY organization_member_roles ADD CONSTRAINT organization_member_roles_pkey PRIMARY KEY (id);
ALTER TABLE ONLY organization_invites ADD CONSTRAINT organization_invites_pkey PRIMARY KEY (id);

ALTER TABLE ONLY organizations ADD CONSTRAINT organizations_app_slug_key UNIQUE (app_id, slug);
ALTER TABLE ONLY organization_members ADD CONSTRAINT organization_members_org_user_key UNIQUE (org_id, user_id);
ALTER TABLE ONLY organization_member_roles ADD CONSTRAINT organization_member_roles_member_role_key UNIQUE (member_id, role_id);
ALTER TABLE ONLY organization_invites ADD CONSTRAINT organization_invites_token_hash_key UNIQUE (token_hash);

ALTER TABLE ONLY organizations
    ADD CONSTRAINT organizations_app_id_fkey FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;
ALTER TABLE ONLY organizations
    ADD CONSTRAINT organizations_created_by_fkey FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE ONLY organization_members
    ADD CONSTRAINT organization_members_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE ONLY organization_members
    ADD CONSTRAINT organization_members_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE ONLY organization_member_roles
    ADD CONSTRAINT organization_member_roles_member_id_fkey FOREIGN KEY (member_id) REFERENCES organization_members(id) ON DELETE CASCADE;
ALTER TABLE ONLY organization_member_roles
    ADD CONSTRAINT organization_member_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE;
ALTER TABLE ONLY organization_invites
    ADD CONSTRAINT organization_invites_org_id_fkey FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE ONLY organization_invites
    ADD CONSTRAINT organization_invites_invited_by_fkey FOREIGN KEY (invited_by) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE ONLY client_sessions
    ADD CONSTRAINT client_sessions_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE SET NULL;

CREATE INDEX idx_organizations_app ON organizations USING btree (app_id);
CREATE INDEX idx_org_members_user ON organization_members USING btree (user_id);
CREATE INDEX idx_org_members_org_status ON organization_members USING btree (org_id, status);
CREATE INDEX idx_org_member_roles_member ON organization_member_roles USING btree (member_id);
CREATE INDEX idx_org_member_roles_role ON organization_member_roles USING btree (role_id);
CREATE INDEX idx_org_invites_org ON organization_invites USING btree (org_id);
CREATE UNIQUE INDEX uq_org_invites_pending ON organization_invites USING btree (org_id, lower(email)) WHERE (status = 'pending'::text);
CREATE INDEX idx_client_sessions_org ON client_sessions USING btree (organization_id) WHERE (organization_id IS NOT NULL);

-- +goose Down
DROP INDEX IF EXISTS idx_client_sessions_org;
ALTER TABLE client_sessions DROP CONSTRAINT IF EXISTS client_sessions_organization_id_fkey;
ALTER TABLE client_sessions DROP COLUMN IF EXISTS organization_id;
DROP TABLE IF EXISTS organization_invites CASCADE;
DROP TABLE IF EXISTS organization_member_roles CASCADE;
DROP TABLE IF EXISTS organization_members CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
ALTER TABLE apps DROP CONSTRAINT IF EXISTS apps_org_creation_policy_check;
ALTER TABLE apps DROP COLUMN IF EXISTS org_creation_policy;
ALTER TABLE apps DROP COLUMN IF EXISTS organizations_enabled;
