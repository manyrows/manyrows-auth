-- +goose Up
ALTER TABLE sessions ADD COLUMN remember_me boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE sessions DROP COLUMN IF EXISTS remember_me;
