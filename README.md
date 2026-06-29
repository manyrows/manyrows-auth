# ManyRows Auth

**English** | [한국어](./README.ko.md)

Self-hostable user authentication you can drop in front of your apps.
Sign-in, password reset, email verification, magic links, OAuth (Google,
Apple, Microsoft, GitHub, Kakao, Naver) plus any OIDC/OAuth2 provider, passkeys,
sessions, audit logs, role-based access - running as a single Go binary
with Postgres.

One install runs many apps. Apps share users through user pools (one
app or several SSO-style), with their own sign-in settings, OAuth
credentials, and roles.

## Quickstart (Docker)

```bash
git clone <this-repo>
cd manyrows
cp .env.example .env       # edit values (especially MANYROWS_FROM_EMAIL)
docker compose up -d
```

Open `http://localhost:8080`. The first registrant becomes the
super-admin - there's no signup flow after that, so claim it before
exposing the install.

If you can't claim before exposure (CI deploys, slow first boot, etc.),
set `MANYROWS_SUPER_ADMIN_EMAIL=you@yourcompany.com` in `.env` before
`docker compose up`. The slot is then pre-claimed at boot and only that
exact email can complete the first registration - random scanners
hitting the install can't take it.

To watch the boot:

```bash
docker compose logs -f web
```

To stop everything (data is preserved in the `manyrows-db` volume):

```bash
docker compose down
```

---

## What you get

- **Sign-in methods** per app: password, OTP code, magic link, OAuth
  (Google / Apple / Microsoft / GitHub / Kakao / Naver), any OIDC/OAuth2
  provider, passkeys.
- **Bring-your-own identity providers** - beyond the six built-in
  social logins, connect any OpenID Connect or OAuth2 provider per app
  (Okta, Auth0, Keycloak, Entra/Azure AD, GitLab, Discord, ...) from the
  admin UI: paste an issuer URL (or explicit endpoints) plus client
  credentials - no code, no release. Covers corporate SSO and the long
  tail. PKCE + nonce, signature/issuer/audience verification, and
  https-only endpoints are enforced for you.
- **Workspace + project + app hierarchy** - one ManyRows install
  groups environments (dev / staging / prod) under projects, and
  projects under workspaces.
- **Role-based access control** - per-project permissions and roles,
  default-role assignment on signup.
- **Organizations (multi-tenant)** - opt-in per app: your end-users
  belong to organizations (their tenants), one user can join many, each
  with a tier (`owner` / `admin` / `member`). Roles and permissions
  resolve within the user's active organization and are re-checked on
  every request, so a removed member or archived org loses access
  immediately. Provision orgs, members, and email invites from your
  backend via the server API, or manage them from the admin dashboard.
- **Session management** - per-app session TTL, cookie-domain control,
  IP allowlists, CORS origin lists, revocation.
- **Audit logs** - every authentication event recorded per
  workspace/app, filterable in the admin AuthLogs view.
- **Embeddable end-user UI** (`@manyrows/appkit-react`) - drop in a
  React component, get a fully wired sign-in screen.
- **Backend SDKs** for Go, Node, Python, and Java - verify end-user
  JWTs locally and call the server API (users, roles, permissions) from
  your own backend. See [Server SDKs](#server-sdks).
- **OpenID Connect provider** - expose any app over standards-
  conformant OIDC. Off-the-shelf libraries (next-auth,
  passport-openidconnect, Spring Security, etc.) integrate by
  pointing at the per-app discovery URL - no ManyRows SDK required.

---

## Screenshots

<p align="center">
  <img src="docs/screenshots/sign-in.png" width="760" alt="End-user sign-in (AppKit)"><br><br>
  <img src="docs/screenshots/admin-dashboard.png" width="760" alt="Admin dashboard"><br><br>
  <img src="docs/screenshots/auth-logs.png" width="760" alt="Auth logs">
</p>

---

## Configuration

All knobs are env vars prefixed `MANYROWS_*`. The full list with
defaults lives in `.env.example`. The minimum a self-hoster needs to
set is `MANYROWS_FROM_EMAIL`; everything else has sane defaults.

A few worth knowing:

| Variable                                          | Default | Notes |
|---------------------------------------------------|---|---|
| `DATABASE_URL` or `MANYROWS_DATABASE_URL`         | (required) | Postgres connection string. |
| `MANYROWS_FROM_EMAIL`                             | (none) | Sender address on outbound mail (admin register, password reset, magic links). **Required for production** - the email service refuses to send with an empty From and logs an error. Use an address on your own domain so DKIM/SPF pass. |
| `MANYROWS_BASE_URL`                               | (auto-pinned) | Pinned automatically on the first `/admin/register`. Set explicitly when behind a known reverse proxy. |
| `MANYROWS_DB_SCHEMA`                              | `manyrowsauth` | Postgres schema. Override if `manyrowsauth` clashes with anything in the database. |
| `MANYROWS_SMTP_HOST`/`PORT`/`USERNAME`/`PASSWORD` | (none) | Outbound mail. Without these, mail is logged to stdout. |
| `MANYROWS_TURNSTILE_ENABLED`                      | `false` | Cloudflare bot challenge on register/login. Off by default. |

### Database tuning

The pool defaults are fine for most installs. Override these when you know why.

| Variable | Default | Notes |
|---|---|---|
| `MANYROWS_POOL_MAX_CONNS` | `20` | Upper bound on the pgxpool. Raise on busy installs; lower behind a connection pooler like PgBouncer. |
| `MANYROWS_POOL_MIN_CONNS` | (pgx default) | Floor on the pool size. Set when cold-start latency matters. |
| `MANYROWS_POOL_MIN_IDLE_CONNS` | (pgx default) | Pre-warmed idle connections held ready for bursts. |
| `MANYROWS_POOL_MAX_CONN_IDLE_TIME_SECONDS` | (pgx default) | Idle pruning. Tighten when your DB charges for connection-minutes. |
| `MANYROWS_POOL_MAX_CONN_LIFETIME_SECONDS` | (pgx default) | Recycle every connection after this many seconds. Useful behind load balancers that drop long-lived TCP. |
| `MANYROWS_POOL_HEALTH_CHECK_PERIOD_SECONDS` | (pgx default) | How often pgx pings idle connections to keep them warm. |
| `MANYROWS_DB_STATEMENT_TIMEOUT_SECONDS` | (server default - usually off) | Postgres `statement_timeout` set on every pooled connection. Bounds the wall-clock any one query can spend before the server cancels it. **Strongly recommend setting this** (start with 30s) - the guardrail against a runaway query pinning a worker forever. |
| `MANYROWS_DB_CONNECT_TIMEOUT_SECONDS` | (pgx default - wait forever) | TCP+TLS handshake bound on new pool connections. Set when your DB IP can flap during a boot race (Fly, Render) so startup fails loudly instead of hanging. 10s is a sensible value. |
| `MANYROWS_DB_APPLICATION_NAME` | `manyrows` | Reported via Postgres's `application_name` GUC; visible in `pg_stat_activity` / `pg_stat_statements`. Override per-deploy when one cluster hosts multiple installs (`manyrows-prod`, `manyrows-staging`). |
| `MANYROWS_DB_SKIP_MIGRATIONS` | `false` | Set to `true` to short-circuit goose on boot. Used by two-step deploys that apply schema separately from the binary rollout - the new binary boots without re-racing migrations the previous deploy already ran. |

Auto-generated on first boot (no setup needed): HMAC keys, encryption
key, OTP pepper. They're persisted to `system_secrets` and reused on
subsequent boots.

---

## Going to production

ManyRows ships as a single static binary with the admin UI and AppKit
runtime embedded - no sidecars, no asset server - so the production
story is short: run it behind a TLS-terminating proxy and point it at
Postgres. The bundled **Docker Compose** stack, a **standalone
container**, and **Heroku** are all production-grade paths (see
[Deployment paths](#deployment-paths) below) - pick whichever matches
your infra.

Whichever you pick, do these five things:

1. **Terminate TLS upstream** - Caddy, Traefik, nginx + certbot,
   Cloudflare proxy, or your platform's load balancer. ManyRows speaks
   plain HTTP behind the proxy.
2. **Forward `X-Forwarded-Proto: https`** so cookies get the `Secure`
   flag and redirect targets are constructed correctly.
3. **Set `MANYROWS_BASE_URL`** to the canonical hostname before going
   live (or let the first `/admin/register` pin it from the request).
4. **Persist `manyrows-db`** - managed Postgres recommended in
   production. If you stay with the bundled compose Postgres, back the
   volume up.
5. **Custom domain + cookie scope** - wire `auth.yourdomain.com` to
   ManyRows so cookies are first-party with your app. Two per-app
   settings in the admin UI:
   - *App → Security → Custom Domain* - set the **Auth domain**
     (e.g. `auth.drumkingdom.com`). Detailed runbook is on that screen.
   - *App → Security → Session transport → Enable cookies → Cookie
     domain* - set this to the **registrable parent domain**
     (`auth.drumkingdom.com` → `drumkingdom.com`). Skip it and the
     session cookie is scoped to the auth subdomain only, so it won't
     be sent on requests from your app's own domain.

### Deployment paths

Every path below runs the same image and reads the same environment
variables ([Configuration](#configuration)); the only real difference is
who runs the container and where Postgres lives.

> **Use your own domain for `MANYROWS_BASE_URL`** - a subdomain of your
> app's registrable domain (`auth.yourdomain.com`), *not* the platform's
> default host. `*.herokuapp.com`, `*.fly.dev`, and `*.onrender.com` are
> on the Public Suffix List, so session cookies set there can't be shared
> first-party with your app - which is the whole point of checklist
> step 5. Every example below assumes `auth.yourdomain.com`.

#### Docker Compose

The bundled `docker-compose.yml` is production-capable, not just a local
demo. Two ways to take it live:

- **Managed Postgres (recommended).** Drop the `db` service and point
  `DATABASE_URL` at your managed instance (RDS, Cloud SQL, Neon,
  Supabase, ...). ManyRows holds no local state, so the `web` service is
  then stateless and trivially restartable.
- **Bundled Postgres.** Keep the `db` service for a small single-host
  install, but change the default `POSTGRES_PASSWORD` (the `.env`
  default is `manyrows`) and back the `manyrows-db` volume up on a
  schedule.

Either way: set a real `MANYROWS_FROM_EMAIL` + SMTP credentials, and put
the `web` service behind one of the reverse proxies below. It already
restarts `unless-stopped`.

#### Standalone container

Any platform that runs an OCI image works - plain `docker run`,
Kubernetes, ECS, Cloud Run, or any orchestrator (Render and Fly.io get
dedicated recipes below):

```bash
docker build -t manyrows .
docker run -d -p 8080:8080 \
  -e DATABASE_URL="postgres://user:pass@host:5432/manyrows?sslmode=require" \
  -e MANYROWS_FROM_EMAIL="auth@yourdomain.com" \
  -e MANYROWS_BASE_URL="https://auth.yourdomain.com" \
  manyrows
```

The binary binds `$PORT` when the platform sets it, falling back to
`8080` - so most PaaS auto-wire the port with no extra config.

#### Heroku

The image is Heroku-ready: it honours `$PORT` and defaults to the `prod`
profile. Heroku's router terminates TLS and sets `X-Forwarded-Proto`, so
checklist steps 1-2 are handled for you either way; the custom-domain
step still applies if you front it with `auth.yourdomain.com`.

**Container registry** - simplest, reuses the `Dockerfile`:

```bash
heroku create your-manyrows
heroku addons:create heroku-postgresql:essential-0   # provisions DATABASE_URL
heroku config:set \
  MANYROWS_FROM_EMAIL="auth@yourdomain.com" \
  MANYROWS_BASE_URL="https://auth.yourdomain.com"
heroku stack:set container
heroku container:push web && heroku container:release web
```

**Binary slug via the Platform API** - no Docker; build a Linux binary
locally and push it as a slug. It releases to an app you've already
created (run the `heroku create` / `addons:create` / `config:set` steps
above first, just skip `stack:set container`), and needs `jq` plus
Heroku credentials in `~/.netrc` (written by `heroku login`). First
build the slug - the UI bundles come from the committed `build-ui.sh`:

```bash
bash ./build-ui.sh || { echo "build-ui failed"; exit 1; }

cd manyrows-core
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
GOARCH=amd64 GOOS=linux go build -ldflags="-X main.Version=${VERSION}" \
  -o ../app/web start.go
cd ..
tar czf slug.tgz ./app   # Heroku expects a top-level ./app dir → /app/web
```

Then create, upload, and release the slug (set `AppID` to your app):

```bash
AppID='your-heroku-app'

slug=$(curl -s -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/vnd.heroku+json; version=3' \
  -d '{"process_types":{"web":"./web"}}' \
  -n "https://api.heroku.com/apps/$AppID/slugs")

curl -X PUT -H 'Content-Type:' --data-binary @slug.tgz "$(jq -r '.blob.url' <<< "$slug")"

curl -X POST \
  -H 'Accept: application/vnd.heroku+json; version=3' \
  -H 'Content-Type: application/json' \
  -d "{\"slug\":$(jq '.id' <<< "$slug")}" \
  -n "https://api.heroku.com/apps/$AppID/releases"
```

#### Render

Render builds straight from the `Dockerfile`, sets `$PORT`, and
terminates TLS + forwards `X-Forwarded-Proto` at its edge - so the
proxy checklist is handled. Commit a `render.yaml` blueprint that
provisions Postgres and wires `DATABASE_URL` for you:

```yaml
databases:
  - name: manyrows-db
    plan: basic-256mb

services:
  - type: web
    name: manyrows
    runtime: docker
    plan: starter
    healthCheckPath: /health
    envVars:
      - key: DATABASE_URL
        fromDatabase:
          name: manyrows-db
          property: connectionString
      - key: MANYROWS_FROM_EMAIL
        value: auth@yourdomain.com
      - key: MANYROWS_BASE_URL
        sync: false   # set to your custom auth domain (auth.yourdomain.com)
```

Then *New → Blueprint* in the dashboard and point it at your repo. The
Dockerfile EXPOSEs `8080` and the binary honours `$PORT`, so the port
wires up with no extra config.

#### Fly.io

`fly launch` reads the `Dockerfile`, picks up its `EXPOSE 8080` as the
`internal_port`, and writes a `fly.toml` with `force_https = true`. Fly
terminates TLS and forwards `X-Forwarded-Proto`, so the proxy checklist
is covered.

```bash
fly launch --no-deploy              # detects the Dockerfile, writes fly.toml
fly postgres create                 # or point DATABASE_URL at Supabase/Neon/Fly MPG
fly postgres attach <pg-app-name>   # sets the DATABASE_URL secret
fly secrets set MANYROWS_FROM_EMAIL=auth@yourdomain.com \
                MANYROWS_BASE_URL=https://auth.yourdomain.com
fly deploy
```

The binary's default port (`8080`) matches the `internal_port` Fly
detects, so there's no `$PORT` wiring to do.

### Reverse-proxy examples

#### Caddy

Auto-managed TLS via Let's Encrypt. Drop into `/etc/caddy/Caddyfile`
and `systemctl reload caddy`:

```caddyfile
auth.example.com {
    reverse_proxy localhost:8080
}
```

That's the whole config - Caddy adds `X-Forwarded-For`,
`X-Forwarded-Proto`, and `X-Forwarded-Host` automatically. If your
ManyRows container is on another host, swap `localhost` for the
internal hostname / IP.

#### nginx

Bring your own cert (certbot, Let's Encrypt DNS-01, internal CA,
whatever). Minimum working config:

```nginx
server {
    listen 80;
    server_name auth.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

`X-Forwarded-Proto $scheme` is the load-bearing line: without it the
binary won't realise requests are HTTPS and the session cookies will
miss the `Secure` flag.

### Upgrades and backups

- **Upgrades.** Pull the new image (or push a new slug) and restart.
  Schema migrations run automatically on boot via goose. For rollouts
  that apply schema separately from the binary, run migrations once
  out-of-band and set `MANYROWS_DB_SKIP_MIGRATIONS=true` on the new
  release so it boots without re-racing them.
- **Backups.** Managed Postgres gives you automated snapshots - use
  them. On the bundled compose Postgres, `pg_dump` on a schedule. The
  auto-generated HMAC/encryption keys and OTP pepper live in the
  database (`system_secrets`), so a Postgres backup captures everything
  - there's no separate keystore to save.
- **Health checks.** Point your platform's liveness/readiness probe at
  `/health` (it also reports the running build version).

---

## Adding login to your app (AppKit)

You don't have to build a sign-in screen. ManyRows ships **AppKit** -
a drop-in end-user auth UI (sign-in, registration, OTP verification,
password reset, profile) that talks to your install. It's an optional
convenience layer for React (with a framework-free runtime too); if you
want full control, call the Client REST API directly. Full reference -
every prop, hook, theming, auth-route handling, the REST API - is at
**<https://manyrows.com/products/auth/docs>**.

> **CORS - required.** AppKit calls ManyRows from *your* app's origin,
> so add your domain (e.g. `https://yourapp.com`) to the app's allowed
> CORS origins in the admin UI (Apps page) - otherwise the browser
> blocks every request.

**React** - `npm i @manyrows/appkit-react`:

```tsx
import { AppKit, AppKitAuthed, useUser } from "@manyrows/appkit-react";

function MyApp() {
  const user = useUser();
  return <p>Welcome, {user?.name || user?.email}</p>;
}

export default function Page() {
  return (
    <AppKit
      workspace="your-workspace"
      appId="your-app-id"
      src="https://auth.yourdomain.com/appkit/assets/appkit.js"
    >
      <AppKitAuthed fallback={null}>
        <MyApp />
      </AppKitAuthed>
    </AppKit>
  );
}
```

Only `workspace` and `appId` are required. Because you're self-hosting,
set the `src` prop to your install's runtime URL - otherwise AppKit
loads the hosted (manyrows.com) runtime by default.

**Without React** - load the runtime and drive `window.ManyRows.AppKit`:

```html
<script src="https://auth.yourdomain.com/appkit/assets/appkit.js" defer></script>
<div id="manyrows-app"></div>
<script>
  window.addEventListener("load", () => {
    window.ManyRows.AppKit.init({
      containerId: "manyrows-app",
      workspace: "your-workspace",
      appId: "your-app-id",
      onState: (s) => {
        if (s.status === "authenticated") {
          console.log("user:", s.appData?.account?.email, "token:", s.jwtToken);
        }
      },
    });
  });
</script>
```

The runtime is served by your own binary at
`/appkit/assets/appkit.js` (embedded - nothing extra to deploy).

---

## Server SDKs

For the **backend** side of your app, official SDKs wrap the
server-to-server API (user lookup, roles, permissions, config delivery)
and verify end-user JWTs locally against your install's JWKS - no
per-request round-trip to ManyRows. The Go SDK also ships webhook
signature verification.

| Language          | Repository                                                          | Install |
|-------------------|--------------------------------------------------------------------|---|
| Go                | [manyrows-auth-go](https://github.com/manyrows/manyrows-auth-go)         | `go get github.com/manyrows/manyrows-auth-go` |
| Node / TypeScript | [manyrows-auth-node](https://github.com/manyrows/manyrows-auth-node)     | from source - see repo |
| Python            | [manyrows-auth-python](https://github.com/manyrows/manyrows-auth-python) | `pip install git+https://github.com/manyrows/manyrows-auth-python.git` |
| Java              | [manyrows-auth-java](https://github.com/manyrows/manyrows-auth-java)     | from source (Java 17+) - see repo |

These are optional: AppKit handles the browser side, and any standard
OIDC client works too (see below). Reach for an SDK when your backend
needs to verify tokens or read users, roles, and permissions in its own
language. Each repo's README has the authoritative install and usage
docs.

---

## Integrating via OpenID Connect

If you'd rather use a standards-conformant OIDC client library than
the AppKit SDK, ManyRows exposes each app as an OpenID Connect
provider. Discovery, authorize, token, userinfo, and end-session
endpoints are all built in; PKCE is required, S256 only; both
confidential (with `client_secret`) and public (PKCE-only) client
modes are supported.

Configure in *App → Auth methods → OIDC*: flip the toggle, optionally
generate a `client_secret` (shown once - copy it then), and add your
RP's callback URL to the redirect-URIs allowlist. The admin tab
surfaces the three values your RP library needs:

| Field | Value pattern |
|---|---|
| Discovery URL | `https://<auth-domain>/.well-known/openid-configuration` |
| Client ID | The app's UUID |
| Client Secret | Generated server-side; copy from the dialog once |

Point any standard OIDC client at the discovery URL and it
self-configures. Example with `next-auth`:

```ts
import { type AuthOptions } from "next-auth";

export const authOptions: AuthOptions = {
  providers: [
    {
      id: "manyrows",
      name: "ManyRows",
      type: "oauth",
      wellKnown: "https://auth.yourdomain.com/.well-known/openid-configuration",
      clientId: process.env.MANYROWS_CLIENT_ID,      // the app UUID
      clientSecret: process.env.MANYROWS_CLIENT_SECRET,
      authorization: { params: { scope: "openid email" } },
    },
  ],
};
```

> **Cookie transport mode required.** OIDC's `/authorize` → sign-in
> → `/authorize/resume` round-trip relies on a same-origin session
> cookie. Switch the app's *Session transport* to cookies before
> enabling OIDC; the admin UI blocks the enable toggle when it isn't.

Coexists with the AppKit SDK - both can authenticate against the
same app in parallel.

---

## Architecture (one paragraph)

Single Go binary (`manyrows-core`) with the admin UI bundle and the
end-user auth UI bundle compiled in via `//go:embed`. Postgres is the
only external dependency - schema lives in `manyrows-core/db/migrations`,
applied at boot via `goose` into a configurable schema (`manyrows` by
default). Admin auth uses cookie sessions; end-user auth issues
JWT bearer tokens (`local` transport) or HttpOnly cookies (`cookie`
transport), selectable per app.

---

## Design notes

The *why* behind the non-obvious decisions - password hashing, DPoP-bound
refresh tokens, verified-email account linking, secrets-at-rest, and the
"standard" features deliberately left out - is written up in
[`docs/design-notes.md`](docs/design-notes.md).

---

## Development

```bash
# Run from source (dev mode, hot reload UI):
cd manyrows-ui && npm install && npm run dev   # in one terminal
cd manyrows-core && go run start.go            # in another

# Run all API tests (needs a dedicated test database):
export TEST_DATABASE_URL="postgres://postgres:postgres@localhost:5432/manyrows_test"
cd manyrows-core
go test ./api/... -count=1

# Run a specific test:
go test -v ./api/... -run "TestCreateProject" -count=1
```

The repo is an npm workspace at the root, so `npm install` from the
top-level pulls deps for `manyrows-ui` and `appkit-ui` in one shot.
`appkit-react` (the published customer SDK) is standalone - it's not
part of the workspace and isn't needed to build or run the server;
install its deps separately when working on it.

---

## License

[GNU Affero General Public License v3.0](./LICENSE) (AGPL-3.0).

You can self-host, modify, and redistribute the code freely. If you
run a modified version as a network service, you must publish your
changes under AGPL-3.0 too - that's the SaaS-loophole-closing clause
specific to AGPL.

A commercial license is available on request for organisations that
can't ship under AGPL terms.
