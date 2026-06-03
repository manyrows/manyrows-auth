-- +goose Up
-- Per-app toggle for credential-guessing defenses on workspace-user login:
-- progressive account lockout and the login-specific per-IP / per-subject
-- rate limit. Defaults TRUE so every existing app stays protected (the
-- protection was previously always-on for all apps). Unlike the QR sign-in /
-- new-device "new surface defaults off" convention, this gates an existing
-- always-on protection, so defaulting off would silently weaken every app.
-- Failed attempts are recorded regardless; this flag only gates enforcement.
ALTER TABLE apps ADD COLUMN brute_force_protection_enabled boolean DEFAULT true NOT NULL;

-- +goose Down
alter table if exists apps drop column if exists brute_force_protection_enabled;
