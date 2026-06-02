import * as React from "react";
import axios from "axios";

// Mirrors AdminAuthConfig in api/adminAuthHandler.go. Public endpoint;
// safe to fetch from unauth pages (login, register, forgot).
export interface AdminAuthConfig {
  turnstileSiteKey: string;
  needsFirstAdmin: boolean;
  // Server build version (e.g. "v0.4.2-3-gabcd123-dirty" when built
  // via build.sh; "dev" for unstamped local runs). Rendered on the
  // auth screens by AuthShell.
  version: string;
}

let cached: AdminAuthConfig | null = null;
let inflight: Promise<AdminAuthConfig> | null = null;

function fetchConfig(): Promise<AdminAuthConfig> {
  if (cached) return Promise.resolve(cached);
  if (inflight) return inflight;
  inflight = axios
    .get<AdminAuthConfig>("/admin/auth/config")
    .then((r) => {
      cached = {
        turnstileSiteKey: r.data?.turnstileSiteKey ?? "",
        needsFirstAdmin: !!r.data?.needsFirstAdmin,
        version: r.data?.version ?? "",
      };
      return cached;
    })
    .catch((e) => {
      inflight = null;
      throw e;
    });
  return inflight;
}

// useAdminAuthConfig returns the public auth config. Returns
// `null` on first render until the fetch completes - callers should
// gate rendering of conditional UI on this being defined.
export function useAdminAuthConfig(): AdminAuthConfig | null {
  const [cfg, setCfg] = React.useState<AdminAuthConfig | null>(cached);
  React.useEffect(() => {
    if (cfg) return;
    let cancelled = false;
    fetchConfig().then((c) => {
      if (!cancelled) setCfg(c);
    });
    return () => {
      cancelled = true;
    };
  }, [cfg]);
  return cfg;
}

// resetAdminAuthConfigCache evicts the cached config so the next
// useAdminAuthConfig() invocation refetches. Call after the
// auth-state-changing actions whose result the config exposes -
// notably register (flips needsFirstAdmin) and logout (so a
// re-login doesn't see the stale "first time here" banner).
export function resetAdminAuthConfigCache(): void {
  cached = null;
  inflight = null;
}
