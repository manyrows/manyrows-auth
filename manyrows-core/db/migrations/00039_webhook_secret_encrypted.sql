-- +goose Up
-- Encrypt webhook signing secrets at rest. Every other sensitive credential
-- (TOTP secrets, OAuth client secrets, SMTP passwords) is stored as an
-- AAD-bound GCM bytea via crypto.SecretEncryptor; webhooks.secret was the lone
-- plaintext exception, so a DB dump leaked every signing key and let an
-- attacker forge payloads any receiver would trust.
--
-- New + rotated webhooks write the ciphertext to secret_encrypted and leave
-- secret = ''. Pre-existing rows keep their plaintext in secret until the next
-- rotate; the dispatcher reads secret_encrypted when present and falls back to
-- the plaintext secret otherwise (read-compat). `web migrate-encryption` does
-- NOT back-fill plaintext rows — it only re-keys already-encrypted columns —
-- so the fallback is what covers legacy rows.
ALTER TABLE webhooks ADD COLUMN secret_encrypted bytea;

-- +goose Down
ALTER TABLE webhooks DROP COLUMN IF EXISTS secret_encrypted;