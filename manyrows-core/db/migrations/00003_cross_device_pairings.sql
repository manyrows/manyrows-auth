-- +goose Up
-- Cross-device sign-in via QR code. The desktop initiates a pairing
-- (no auth needed — anonymous start), gets back an opaque pairing_id
-- it polls on, plus a one-time pairing_code rendered as a QR. The
-- user scans the code on their phone, signs in if they aren't already,
-- and approves the pairing. The desktop's next poll mints a fresh
-- session bound to the approver's user_id with the desktop's IP/UA.
--
-- Both halves are atomic + single-use: /approve consumes the pending
-- pairing by code_hash; /wait consumes the approved pairing by id.
-- Same UPDATE-WHERE-RETURNING pattern as oidc_auth_codes (audit-tested
-- on the OIDC branch).

CREATE TABLE cross_device_pairings (
    id uuid NOT NULL,
    code_hash text NOT NULL,
    app_id uuid NOT NULL,
    initiator_ip text DEFAULT ''::text NOT NULL,
    initiator_user_agent text DEFAULT ''::text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    approved_user_id uuid,
    approver_ip text DEFAULT ''::text NOT NULL,
    approver_user_agent text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    approved_at timestamp with time zone,
    consumed_at timestamp with time zone,
    CONSTRAINT cross_device_pairings_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'denied'::text]))),
    CONSTRAINT cross_device_pairings_expires_after_create CHECK ((expires_at > created_at))
);

ALTER TABLE ONLY cross_device_pairings
    ADD CONSTRAINT cross_device_pairings_pkey PRIMARY KEY (id);

ALTER TABLE ONLY cross_device_pairings
    ADD CONSTRAINT cross_device_pairings_app_id_fkey FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

ALTER TABLE ONLY cross_device_pairings
    ADD CONSTRAINT cross_device_pairings_approved_user_id_fkey FOREIGN KEY (approved_user_id) REFERENCES users(id) ON DELETE SET NULL;

-- Janitor sweep index.
CREATE INDEX idx_cross_device_pairings_expires ON cross_device_pairings USING btree (expires_at);

-- Partial index: pending-pairing lookup by code_hash during /approve.
-- Rows trail off fast (90s TTL + grace), partial form keeps the
-- working set tiny.
CREATE INDEX idx_cross_device_pairings_pending ON cross_device_pairings USING btree (code_hash) WHERE (status = 'pending'::text);

-- +goose Down
drop table if exists cross_device_pairings cascade;
