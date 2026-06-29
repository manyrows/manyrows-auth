# Design notes

ManyRows Auth is built by one developer, in the open, for a domain where the
defaults are often wrong and the "obvious" feature is sometimes the one you
shouldn't ship. This document records the non-obvious decisions: the *why*, not
the *what*. (The [README](../README.md) and the [docs](https://manyrows.com/products/auth/docs)
cover what it does and how to use it.)

Each entry has the same shape: the decision, the alternative we rejected, and the
reasoning.

## Passwords

### Argon2id, with the cost parameters baked into every hash

Passwords are hashed with Argon2id at 64 MiB of memory, 3 iterations, and a single
lane (comfortably above OWASP's documented minimums), stored in PHC string form:
`$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>`. We rejected bcrypt (no
memory-hardness, and a 72-byte input truncation) and PBKDF2 (cheap to attack on
GPUs).

Memory-hardness is what makes large-scale GPU and ASIC cracking expensive; the
parameters are tuned to roughly 50 ms per hash on a server CPU. Encoding them
*into each hash* rather than pinning one global constant means the cost can be
raised later without breaking old hashes: every stored hash keeps verifying
against the parameters baked into it, while new hashes use the stronger settings.
(Upgrading the *existing* hashes to the higher cost is a deliberate migration;
they don't silently re-hash themselves, and lowering the cost would need one too.)
Verification also burns a dummy hash on the no-such-user path, so response time
doesn't leak whether an email is registered.

### Strength by estimation, not by character-class rules

We reject weak passwords using a zxcvbn-style guessability score (the threshold is
configurable per app) plus a length floor, with the user's own email and name fed
in as dictionary inputs. We do *not* impose "one uppercase, one digit, one symbol"
composition rules.

Composition rules produce `Password1!`, predictable to an attacker and annoying to
everyone else, while rejecting genuinely strong passphrases that happen to miss a
class. Estimating how *guessable* a password actually is gets at the thing we care
about, instead of a proxy for it.

### Reuse blocking is a per-app opt-in, off by default

An app can choose to block a user's five most recent passwords, enforced on both
the authenticated change and the reset flow. The toggle defaults to off, and
turning it on still brings no forced rotation, no expiry, and no composition
rules. We rejected making reuse prevention default-on (or mandatory).

Reuse history is friction with a narrow payoff; its real constituency is
operators whose compliance regime demands it, so it's theirs to switch on. One
detail matters for that choice: history is recorded (append, prune to five)
even while the toggle is off, so enabling it later enforces against the user's
actual recent passwords instead of starting from an empty ledger.

## Tokens and sessions

### Stateless JWTs for verification, stateful sessions for revocation

An API request is carried by a short-lived JWT signed with ES256 and published at
`/.well-known/jwks.json`, so the manyrows-go SDK (or any JWKS-aware verifier) can
validate it locally with no call back to us. Behind that token sits a server-side
session row and a refresh token we can revoke at any moment; access tokens are
issued under a per-app issuer (derived from each app's auth domain), and their
expiry is capped at the session's own.

The two extremes are both worse: a long-lived stateless JWT *as* the session can't
be revoked, and a database lookup on every request is slow and couples every
relying party to our database. Splitting the two gets both properties: cheap,
offline verification and real revocation. The short access-token TTL bounds how
long a revoked-but-unexpired token keeps working; the refresh exchange is where
revocation actually bites.

### Session tokens live in HttpOnly cookies, scoped to one registrable domain

In the browser flow the access token (`mr_at_<app>`) and refresh token
(`mr_rt_<app>`) are delivered as `HttpOnly`, `Secure`, `SameSite=Lax` cookies — an
app can tighten `SameSite` to `Strict` — rather than handed to page JavaScript to
hold. When a workspace runs several apps under one parent domain, the cookie
`Domain` can be widened to a shared parent (`.example.com`) so the session follows
the user across subdomains; that value is checked against the Public Suffix List,
and a bare suffix like `.co.uk` or `.github.io` is refused.

`HttpOnly` is the decision that matters here: a token in `localStorage` is readable
by any script on the page, so a single XSS bug exfiltrates it, whereas an
`HttpOnly` cookie is sent automatically and never exposed to JavaScript. The
public-suffix check guards the `Domain` widening — without it an operator could
scope a cookie to `.co.uk` and leak sessions to every unrelated site under it. That
same registrable-domain ceiling is why cross-domain SSO is out of scope (below): a
cookie can't safely reach further.

### Refresh tokens are bound to the device that holds them (DPoP)

The refresh token is the high-value theft target: a bearer refresh token mints new
access tokens indefinitely. So we bind it to a non-extractable browser keypair with
DPoP (RFC 9449) — each refresh carries a fresh proof signed by that key, checked
against the thumbprint (RFC 7638) stored with the token, replays rejected and the
accepted clock skew kept asymmetric (generous into the past, tight into the future)
so a captured proof can't extend its own life. An exfiltrated refresh token is then
inert without the device that issued it. Binding access tokens too (the `cnf`/`ath`
half of the spec) is deferred — see "Still open".

## Identity and OAuth

### Verified email is the account-linking key

A social or OAuth sign-in only merges into an existing account when the provider
asserts the email is *verified*; password login likewise requires a verified
email; and a social sign-in that arrives with no email at all is refused rather
than guessed. We rejected the friendlier-looking option of linking on a raw email
match regardless of verification.

This is the account-takeover seam. If we linked on an *unverified* provider email,
an attacker who can make some provider assert `victim@example.com` (unverified)
would walk straight into the victim's account. Provider verification (or, for
password login, our own) is the ownership proof that closes it. (A friendlier path
that lets a user *prove* an unverified email with their existing password instead
of being rejected is on the roadmap; until it lands, refusing is the safe default.)

### Changing an account's email takes a code from each address

An email change completes only with two verification codes: one sent to the new
address and one sent to the current one. We rejected the common pattern of
confirming the new address alone.

The new-address code only proves the user controls where the account is *going*;
it says nothing about whether the change is sanctioned by whoever owns the
account *now*. With a stolen session, "confirm the new address" lets an attacker
silently re-point the account at an inbox they control — taking every recovery
path with it. The old-address code keeps the current owner in the loop at
exactly the moment the account is being re-keyed.

### Bespoke Kakao and Naver, next to a generic OIDC/OAuth2 client

Google, Apple, Microsoft, GitHub, Kakao, and Naver are built as first-class
providers, while everything else connects through a generic "bring your own OIDC
or OAuth2 IdP" path configured from the admin UI. Kakao and Naver were built
bespoke *even after* the generic path existed; we rejected folding them into it.

Korean users expect the exact branded buttons (yellow Kakao, green Naver), and each
provider has response quirks the generic path would have to special-case
regardless: Naver nests the identity under `response.*`, Kakao under
`kakao_account.*`. A little duplication bought correct UX and explicit, readable
handling of each provider's shape. The generic path earns its keep on the long
tail (Okta, Auth0, Keycloak, Entra), where "paste the issuer URL and client
credentials" is exactly the right amount of configuration.

## Data and tenancy

### Your data stays in your Postgres

Users, sessions, audit logs, roles, config: all of it lives in an ordinary Postgres
schema (`manyrowsauth` by default) you can query, join, and export in plain SQL.
There is no proprietary data layer or export gate between an operator and their own
data. The hierarchy (workspace → project → app, with user *pools* that let several
apps share one identity base) is modeled in normal relational tables, so operator
reporting is just SQL.

Self-hosting is the whole point; lock-in through a proprietary store would defeat
it.

### Organizations are app-scoped tenant data, not identity

Multi-tenant organizations (members, org roles, invites) are opt-in per app, with
a per-app creation policy (self-serve, invite-only, or admin-only). An org belongs
to exactly one app; identity stays at the pool, and an org only partitions usage
of its app. We rejected scoping orgs to the pool, where they'd sit next to the
users they group.

A user is *who someone is*; an org is *which tenant they're acting in*. The two
customer shapes turn out to be disjoint: B2B SaaS apps that need orgs run them in
one app, while the customers who share a pool across several products are
single-tenant ("everyone is implicitly one org") and never turn orgs on. So orgs
can live at the app grain without ever being duplicated — and identity stays
singular at the pool: one human, one login, even across apps sharing that pool.
Orgs spanning multiple apps via a shared pool is an explicit non-goal; if a
multi-product customer ever needs unified tenants, that's a pool-level layer
*above* app orgs, not a reason to hoist orgs out of the app now.

### Secrets at rest are bound to where they live

Secrets (TOTP seeds, OAuth client secrets, SMTP passwords) are sealed with AES-GCM.
The GCM additional-authenticated-data is the secret's *storage location*
(`table:column:id`), and a short key id is derived from the key so a rotation
can tell which key sealed each row. We rejected plain column encryption
with no context binding.

Binding the ciphertext to its location means a value lifted out of one row and
pasted into another (a row-swap or confused-deputy attempt) simply fails to
decrypt, because the authenticated location no longer matches. Keys are generated
on first boot and persisted when the operator doesn't supply them, and rotation is
deliberately explicit, shaped by what each key protects. The data-encryption key
guards stored ciphertext, so a changed value *refuses to boot* unless the old key
is listed in `PREVIOUS_ENCRYPTION_KEYS` alongside an explicit migration run —
better no service than silently writing under a key that can't read the existing
rows. Session keys and the OTP pepper only verify incoming material, so they
rotate in place: the old value sits in a `_PREVIOUS` variable for a grace window
during which both generations verify, then gets removed.

## Deliberately not built

The omissions are decisions too. Some "standard" auth features are actively
harmful, and leaving them out is a position, not an oversight.

- **No forced password rotation or composition rules.** NIST SP 800-63B
  explicitly recommends *against* periodic expiry and complexity mandates: they
  nudge users toward predictable patterns (`Spring2026!`) and add friction
  without buying real security. We check strength once, well, and then leave
  good passwords alone. (Reuse *history* used to be on this list; it now exists
  as a per-app opt-in for compliance-bound operators — see the Passwords section
  — but stays off by default for the same reason.)
- **No SMS one-time codes.** SMS is phishable and SIM-swappable; offering it as a
  "second factor" mostly manufactures false confidence. The investment goes into
  TOTP and passkeys, which are phishing-resistant.
- **No cross-domain SSO.** Sharing one session across *different* registrable
  domains needs third-party cookies (dying in Safari and Chrome) or brittle
  redirect dances. We scope shared sessions to a single registrable domain
  (`*.example.com`) and state the boundary honestly rather than ship something
  browsers are actively dismantling.

## Still open

Decisions not yet made, recorded so they aren't mistaken for oversights:

- **Pool-as-SSO-realm:** same-domain single sign-on across the apps in a pool, via
  a revocable pool session that mints the existing per-app sessions (purely
  additive to the model above).
- **Link-on-sign-in:** let an emailless social sign-in prove ownership of an email
  with a password (or a fresh registration) instead of being refused.
- **DPoP phase 2:** extend the binding from refresh tokens to access tokens
  (`cnf` + `ath`).
- **Scope-gated OIDC tokens and userinfo:** the OIDC provider stores the granted
  scope with each refresh-token chain (in progress), but access tokens don't yet
  carry a scope claim and `/oidc/userinfo` doesn't yet filter its response by
  what was granted.
