# manyrows-appkit

**This is not a publishable npm package.** It's the embedded auth runtime
that gets built, bundled into a single self-contained JS file, and served
from a ManyRows install at `${install}/appkit/assets/appkit.js`. The
package is marked `private: true` on purpose.

If you're an end user, you don't install this — you use
[`@manyrows/appkit-react`](../appkit-react), which loads this runtime at
page-load time.

## How it fits in

```
┌─────────────────────────────────────────────────────────────────┐
│                         customer site                            │
│                                                                  │
│  import { AppKit } from "@manyrows/appkit-react"                │
│  <AppKit workspace="..." appId="..." />                          │
│                                                                  │
│         │  appkit-react dynamic-injects a <script> tag           │
│         │  pointing at the install's hosted bundle:              │
│         ▼                                                        │
│  https://app.example.com/appkit/assets/appkit.js                 │
│                                                                  │
│         │  the script runs, sets window.ManyRows.AppKit          │
│         ▼                                                        │
│  window.ManyRows.AppKit.init({...})                              │
│     → renders the auth UI into a container element               │
│     → manages tokens / refresh / logout                          │
│     → calls back into appkit-react via onJWT / onState           │
└─────────────────────────────────────────────────────────────────┘
```

The bundle ships with its own React + CSS inlined. It runs in its own
DOM subtree (a `<div>` the SDK mounts into) — it does not share a React
tree with the host page. That's why this package has `react` and
`react-dom` as `dependencies` (not `peerDependencies`): nobody is
expected to "provide" React; the runtime brings its own.

## Where the bundle ends up

1. `npm run build` (in this directory) → `dist/appkit/assets/appkit.js`.
2. The repo-root `build.sh` copies that into
   `manyrows-core/appkit/appkit/assets/` so the Go binary embeds it.
3. The Go server serves it at `/appkit/assets/appkit.js`.

## Public API (what `init()` exposes)

The runtime publishes one entry point on the global namespace:

```js
window.ManyRows.AppKit.init(options): Handle
```

Authoritative shape lives in `src/main.tsx`:

- `AppKitOptions` — the input object (`workspace`, `appId`, `container`
  or `containerId`, optional `theme` / `labels` / `renderAuthed` /
  `initialScreen`, plus callbacks for `onReady` / `onError` / `onJWT` /
  `onState` / `onLogin` / `onLogout` / etc.).
- `ManyRowsAppKitHandle` — what `init()` returns (`info()`,
  `getState()`, `subscribe()`, `refresh()`, `logout()`,
  `showProfile()`, `hideProfile()`, `destroy()`).
- Versioned via `APPKIT_VERSION` in `src/main.tsx`. `appkit-react`'s
  `EXPECTED_RUNTIME_VERSION` constant pins which runtime versions it
  accepts; bump both together on a breaking change.

End users should treat `@manyrows/appkit-react`'s typed wrapper as the
public surface, not these internals.

## Local development

```bash
npm install
npm run dev      # vite dev server on :5174, hot-reload
npm run build    # produces dist/appkit/assets/appkit.js
npm run lint
```

The dev server is fine for working on the auth UI in isolation. To
test end-to-end against the customer flow, run the repo-root
`build.sh` and let `manyrows-core` serve the bundle.

## Not-FAQs

**Why isn't this on npm?** Because there's nothing on the customer
side to install. The runtime is served at runtime from the install's
own origin. `@manyrows/appkit-react` is the npm-published consumer-
facing surface.

**Why is React a `dependency` not a `peerDependency`?** Because this
bundle is self-contained — it does not rely on a host React tree.
`peerDependencies` would mean "consumer provides React"; there is no
consumer in the npm sense.

**Where should I add a new public option?** In `src/main.tsx`
(`AppKitOptions` interface) and mirror the type in
`appkit-react/src/types.ts` (`AppKitInitOptions` private type)
so the React wrapper's prop surface stays in sync.
