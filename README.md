# ManyRows Auth

Self-hostable user authentication you can drop in front of your apps.
Sign-in, password reset, email verification, magic links, OAuth (Google,
Apple, Microsoft, GitHub), passkeys, sessions, audit logs, role-based
access - running as a single Go binary with Postgres.

One install runs many apps. Apps share users through user pools (one
app or several SSO-style), with their own sign-in settings, OAuth
credentials, and roles.

> **Honest status.** ManyRows Auth is built by one developer. It runs
> in production today - it powers sign-in for
> [DrumKingdom.com](https://drumkingdom.com) and
> [JerryLingo.com](https://jerrylingo.com) - but there's no QA team, no SLA, and no claim it's
> bug-free. Run it, kick the tyres, and satisfy yourself it holds up
> before you put it in front of anything that matters. If something
> breaks or feels wrong, that's a bug I want to hear about.
>
> **Help shape it.** Issues, reproductions, and PRs are genuinely
> welcome - real-world use is what hardens an auth system. If it
> almost-but-not-quite fits your case, say so; that feedback moves the
> roadmap more than anything.
>
> **Why open source.** Authentication is security-critical
> infrastructure - you shouldn't have to trust a black box with your
> users' credentials. Open source means anyone can audit exactly what
> the binary does, self-host it with no vendor lock-in, and fork it if
> I ever step away. AGPL-3.0 keeps it that way; a commercial license is
> available if those terms don't fit (see *License*).
>
> **Your data.** It's your Postgres. Users, sessions, audit logs -
> query, join, export, or build on them directly in plain SQL. No
> proprietary API, rate-limited dashboard, or export fee stands
> between you and the data you own.

---

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
  (Google / Apple / Microsoft / GitHub), passkeys.
- **Workspace + project + app hierarchy** - one ManyRows install
  groups environments (dev / staging / prod) under projects, and
  projects under workspaces.
- **Role-based access control** - per-project permissions and roles,
  default-role assignment on signup.
- **Session management** - per-app session TTL, cookie-domain control,
  IP allowlists, CORS origin lists, revocation.
- **Audit logs** - every authentication event recorded per
  workspace/app, filterable in the admin AuthLogs view.
- **Embeddable end-user UI** (`@manyrows/appkit-react`) - drop in a
  React component, get a fully wired sign-in screen.
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
| `MANYROWS_DB_SCHEMA`                              | `manyrows` | Postgres schema. Override if `manyrows` clashes with anything in the database. |
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

The Docker compose stack is for local evaluation. For a real deploy:

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

---

## Adding login to your app (AppKit)

You don't have to build a sign-in screen. ManyRows ships **AppKit** -
a drop-in end-user auth UI (sign-in, registration, OTP verification,
password reset, profile) that talks to your install. It's an optional
convenience layer for React (with a framework-free runtime too); if you
want full control, call the Client REST API directly. Full reference -
every prop, hook, theming, auth-route handling, the REST API - is at
**<https://manyrows.com/docs>**.

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
