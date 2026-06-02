# @manyrows/appkit-react

React SDK for Manyrows AppKit. Drop-in authentication, user profiles, roles, permissions, and feature flags for your app — one component, one admin panel.

## Installation

```bash
npm install @manyrows/appkit-react
```

## Quick Start

```tsx
import { AppKit, AppKitAuthed, useUser } from "@manyrows/appkit-react";

function MyApp() {
  const user = useUser();

  return (
    <div>
      <header style={{ padding: 16 }}>
        <h1>My App</h1>
      </header>
      {user && <p>Welcome, {user.name || user.email}</p>}
    </div>
  );
}

export default function Page() {
  return (
    <AppKit workspace="acme" appId="your-app-id">
      <AppKitAuthed fallback={null}>
        <MyApp />
      </AppKitAuthed>
    </AppKit>
  );
}
```

Only `workspace` and `appId` are required. The runtime script loads automatically.

### Convenience Hooks

Access common data without drilling into `snapshot`:

```tsx
import {
  useUser,         // user's account (email, name)
  useRoles,        // string[] of roles
  usePermissions,  // string[] of permissions
  usePermission,   // check a single permission: usePermission("edit")
  useRole,         // check a single role: useRole("admin")
  useFeatureFlags, // all feature flags
  useFeatureFlag,  // check one flag: useFeatureFlag("dark-mode")
  useConfig,       // all config values
  useConfigValue,  // single config: useConfigValue("api-url", "default")
  useToken,        // JWT token for API calls
  useAuthFetch,    // fetch wrapper with automatic Bearer token
  useUpdateProfile,// update the signed-in user's name/email
  useSetPassword,  // set or change the signed-in user's password
} from "@manyrows/appkit-react";
```

### Auth Patterns

**Option A (recommended):** Use `<AppKitAuthed>` to gate authenticated content:

```tsx
<AppKit workspace="acme" appId="your-app-id">
  <AppKitAuthed fallback={null}>
    <MyApp />
  </AppKitAuthed>
</AppKit>
```

**Option B:** Gate manually with `useAppKit()`:

```tsx
<AppKit workspace="acme" appId="your-app-id">
  {useAppKit().isAuthenticated ? <MyApp /> : null}
</AppKit>
```

---

## `<AppKit>` Props

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `workspace` | `string` | required | Workspace slug. |
| `appId` | `string` | required | App ID. |
| `baseURL` | `string` | **required** | ManyRows install hostname (e.g. `https://auth.yourdomain.com`). |
| `theme` | `AppKitTheme` | — | Colors, font, light/dark/auto. See below. |
| `publicAccess` | `boolean` | `false` | Render children regardless of auth state. Use for apps with optional login. |
| `hideAuthUI` | `boolean` | auto | Hide the runtime's built-in login UI. Auto-derived when `authRoutes` is set. |
| `authRoutes` | `Partial<Record<"login"\|"register"\|"forgot-password", string>>` | — | Map auth screens to URL paths. AppKit auto-routes between them. |
| `authRedirect` | `string` | — | When set with `authRoutes`, redirects here after a successful auth. |
| `initialScreen` | `"login"\|"register"\|"forgot-password"` | — | Which screen to show first (overrides `authRoutes`). |
| `onScreenChange` | `(screen) => void` | — | Called when the user navigates between auth screens. |
| `authHeader` | `ReactNode` | — | Custom content rendered above the login/register card. |
| `labels` | `Record<string, string>` | — | Override any user-facing string in the auth UI. |
| `embedded` | `boolean` | `false` | Render the auth form inline instead of full-viewport. **(New in 1.3.0)** |
| `loading` | `ReactNode` | spinner | Custom loading UI while the runtime boots. |
| `errorUI` | `(err) => ReactNode` | built-in | Custom error UI. |
| `hideLoadingUI` | `boolean` | `false` | Suppress the default spinner. |
| `hideErrorUI` | `boolean` | `false` | Suppress the default error display. |
| `runtimeMinVersion` | `string` | — | Pin a minimum runtime version (semver). |
| `silent` | `boolean` | `false` | Suppress console warnings. |
| `debug` | `boolean` | `false` | Verbose console logging. |
| `onReady` | `(info) => void` | — | Called when the runtime mounts. |
| `onError` | `(err) => void` | — | Called on errors. |
| `onState` | `(snapshot) => void` | — | Called on every snapshot change. |
| `onReadyState` | `(snapshot) => void` | — | Called when authenticated and `appData` is available. |
| `className` | `string` | — | Class on the wrapper div. |
| `style` | `CSSProperties` | — | Inline styles on the wrapper div. |
| `children` | `ReactNode` | — | Authed-state UI (gated by `<AppKitAuthed>`). |

See [API.md](./API.md) for full type definitions.

### Theming

```tsx
<AppKit
  workspace="acme"
  appId="your-app-id"
  theme={{
    primaryColor: "#7c3aed",
    backgroundColor: "#fafafa",
    colorMode: "auto",          // "light" | "dark" | "auto"
  }}
>
  ...
</AppKit>
```

Richer branding — custom fonts, corner radius, card background, custom CSS,
and white-label (removing the "Powered by ManyRows" badge) — is a paid feature
configured per-app in the ManyRows admin panel and applied automatically. It is
not set through this client prop.

### Embedded mode (new in 1.3.0)

By default, the auth form fills the viewport (`min-height: 100vh`, vertically centered). For embedded contexts — sidebars, modals, inline sections — set `embedded` to flow naturally inside its container:

```tsx
<aside style={{ width: 380 }}>
  <AppKit workspace="acme" appId="your-app-id" embedded>
    <AppKitAuthed fallback={<LoginPrompt />}>
      <ProfileSummary />
    </AppKitAuthed>
  </AppKit>
</aside>
```

`embedded` strips the full-viewport wrapper, vertical centering, and the `var(--ak-color-bg)` background — the form sits where you put it.

### Auth on dedicated routes

Wire login / register / forgot-password to URL paths and AppKit handles routing between them:

```tsx
<AppKit
  workspace="acme"
  appId="your-app-id"
  authRoutes={{
    login: "/login",
    register: "/signup",
    "forgot-password": "/forgot",
  }}
  authRedirect="/dashboard"
>
  <App />
</AppKit>
```

Visiting `/signup` opens the register screen; clicking "Sign in" updates the URL to `/login`; logging in redirects to `/dashboard`.

### Transport mode (server-driven)

How the session token reaches the browser is configured **per app on the server**, not as a prop here:

- **Local** (default) — JWT in `localStorage`, sent as `Authorization: Bearer`. The historical AppKit shape; works anywhere.
- **First-party cookie** — `mr_at` / `mr_rt` `HttpOnly; Secure; SameSite=Lax` cookies. The token never reaches JS. Works when the auth host and your app share a registrable domain (same-host deploy or `auth.yourdomain.com` via custom-domain CNAME).
- **Backend proxy (BFF)** — your backend proxies AppKit calls to ManyRows server-to-server and sets its own session cookie on its own origin. Advanced; surfaced via the API only.

The mode comes back in the boot response (`/a/app/me`'s `transportMode` field) and AppKit configures fetch + storage automatically. There is **no `cookieMode` / `transport` prop** on `<AppKit>` — the operator picks the mode in the admin UI under **Security → Sessions → Transport** and the SDK just does the right thing on the next page load.

### Performance: no API call when logged out (since 1.2.0)

In **local** mode, when there's no token in `localStorage` and the user isn't on an auth route, AppKit emits an `unauthenticated` snapshot immediately and **skips loading the runtime script entirely**. No `appkit.js` download, no `/me` API call. The runtime lazy-loads only when the user navigates to an auth route or a token appears.

This is automatic — you don't need to configure anything. For embedders mounting `<AppKit>` on public marketing pages, it means zero ManyRows traffic on anonymous visits.

In **cookie** and **bff** modes there's no JS-readable signal of an existing session, so AppKit always loads the runtime to check via the cookie. The runtime itself is small and cached after first load.

---

## Reference

For full type definitions, callback signatures, and runtime version pinning, see [API.md](./API.md).

## License

MIT
