-- +goose Up
-- Naver (nid.naver.com) is OAuth2-only and exposes NO email-verification
-- flag at all — unlike every other provider (Google/Apple verify, GitHub
-- filters to verified, Microsoft uses xms_edov, Kakao has is_email_verified).
-- Treating Naver's account email as verified unconditionally let a Naver
-- account asserting a victim's address hijack an existing account via the
-- email-fallback link in ResolveOAuthSignInIdentity. Naver sign-in now
-- requires this per-app opt-in: the operator explicitly trusts Naver's emails
-- for this app. Mirrors external_idps.trust_unverified_email.
--
-- Default false = secure (Naver sign-in is refused until an admin opts in).
-- The flag is opt-IN to trusting Naver's email, so omitting it can never
-- weaken the check; existing apps with Naver configured will refuse Naver
-- sign-in until an admin ticks the box (intended — they were trusting an
-- unverifiable address before).
ALTER TABLE apps ADD COLUMN naver_trust_unverified_email boolean DEFAULT false NOT NULL;

-- +goose Down
ALTER TABLE apps DROP COLUMN IF EXISTS naver_trust_unverified_email;
