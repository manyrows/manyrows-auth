-- +goose Up
-- Passwordless account deletion: social/passkey-only users (no password)
-- confirm an erasure request with a one-time code emailed to their verified
-- address. One pending request per user (ON CONFLICT (user_id) in the repo);
-- 15-minute TTL swept by the janitor. Cascades away if the user is deleted.
CREATE TABLE account_delete_requests (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    app_id uuid NOT NULL,
    code_hash text NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE ONLY account_delete_requests
    ADD CONSTRAINT account_delete_requests_pkey PRIMARY KEY (id);

ALTER TABLE ONLY account_delete_requests
    ADD CONSTRAINT account_delete_requests_user_id_key UNIQUE (user_id);

ALTER TABLE ONLY account_delete_requests
    ADD CONSTRAINT account_delete_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE ONLY account_delete_requests
    ADD CONSTRAINT account_delete_requests_app_id_fkey FOREIGN KEY (app_id) REFERENCES apps(id) ON DELETE CASCADE;

-- +goose Down
DROP TABLE IF EXISTS account_delete_requests;
