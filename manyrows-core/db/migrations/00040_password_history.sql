-- +goose Up
-- Password reuse prevention.
--   password_history: rolling record of each user's most recent password
--   hashes (newest 5 kept; pruned on append). Recorded on every successful
--   user-facing password set REGARDLESS of the per-app toggle, so enabling
--   the toggle later has history to enforce against.
--   apps.password_reuse_prevention: per-app toggle; when true, the user-
--   facing set/reset paths reject any of the newest 5 recorded hashes.
CREATE TABLE password_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    password_hash text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY password_history ADD CONSTRAINT password_history_pkey PRIMARY KEY (id);
ALTER TABLE ONLY password_history ADD CONSTRAINT password_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

CREATE INDEX idx_password_history_user_created ON password_history (user_id, created_at DESC);

ALTER TABLE apps ADD COLUMN password_reuse_prevention boolean DEFAULT false NOT NULL;

-- +goose Down
ALTER TABLE apps DROP COLUMN IF EXISTS password_reuse_prevention;
DROP TABLE IF EXISTS password_history;
