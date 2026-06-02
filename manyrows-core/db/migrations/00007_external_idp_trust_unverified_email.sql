-- +goose Up
-- Per-IdP opt-out for the verified-email requirement. The callback
-- normally refuses a sign-in unless the IdP marked the email verified
-- (defends against account-takeover via the email-fallback link). Some
-- trusted IdPs — e.g. a corporate Okta that verifies emails but doesn't
-- emit the email_verified claim — would be blocked. An admin can flip
-- this to trust the IdP's email without the claim.
--
-- Default false = secure (require verified). The flag is opt-IN to
-- trusting unverified emails, so omitting it can never weaken the check.
ALTER TABLE external_idps ADD COLUMN trust_unverified_email boolean DEFAULT false NOT NULL;

-- +goose Down
ALTER TABLE external_idps DROP COLUMN IF EXISTS trust_unverified_email;
