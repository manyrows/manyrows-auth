-- +goose Up
-- Per-API-key token-bucket state for the server-API rate limiter, moved out
-- of process memory so the budget is shared across all replicas. The old
-- in-memory limiter gave each instance its own full budget, so a leaked key
-- effectively got N x the configured rate under N replicas. One row per key;
-- transient operational state, no FK (mirrors the `attempts` table).
CREATE TABLE api_key_rate_limits (
    api_key_id  uuid PRIMARY KEY,
    tokens      double precision NOT NULL,
    last_refill timestamp with time zone NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE api_key_rate_limits;
