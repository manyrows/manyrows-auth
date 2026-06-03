-- +goose Up
-- New Device Detection: remember the devices each user has signed in from
-- (per app), keyed by a user-agent fingerprint, so a login from a
-- previously unseen device can raise a security-alert email.
--
-- Devices are recorded on every login regardless of the per-app toggle, so
-- the table stays warm: when an operator later flips
-- apps.new_device_alerts_enabled on, already-seen devices won't be
-- mistaken for new ones. The toggle ships off (matching the QR sign-in /
-- 2FA "new surface defaults disabled" convention) and only gates whether
-- the alert email is sent.

CREATE TABLE client_known_devices (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    app_id uuid NOT NULL,
    ua_hash text NOT NULL,
    user_agent text DEFAULT ''::text NOT NULL,
    last_ip text DEFAULT ''::text NOT NULL,
    first_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY client_known_devices
    ADD CONSTRAINT client_known_devices_pkey PRIMARY KEY (id);

-- One row per (user, app, device). The prefix (user_id, app_id) also serves
-- the "how many devices does this account have for this app" count.
ALTER TABLE ONLY client_known_devices
    ADD CONSTRAINT client_known_devices_user_app_ua_key UNIQUE (user_id, app_id, ua_hash);

ALTER TABLE ONLY client_known_devices
    ADD CONSTRAINT client_known_devices_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE ONLY client_known_devices
    ADD CONSTRAINT client_known_devices_app_id_fkey FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE apps ADD COLUMN new_device_alerts_enabled boolean DEFAULT false NOT NULL;

-- +goose Down
drop table if exists client_known_devices;
alter table if exists apps drop column if exists new_device_alerts_enabled;
