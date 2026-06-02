import React from "react";
import axios from "axios";

// Cloudflare Turnstile - bot challenge widget.
// Public docs: https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/

declare global {
  interface Window {
    turnstile?: {
      render: (container: HTMLElement | string, options: Record<string, unknown>) => string;
      reset: (widgetId?: string) => void;
      remove: (widgetId?: string) => void;
    };
  }
}

const SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

let scriptLoadPromise: Promise<void> | null = null;

function loadTurnstileScript(): Promise<void> {
  if (window.turnstile) return Promise.resolve();
  if (scriptLoadPromise) return scriptLoadPromise;

  scriptLoadPromise = new Promise((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${SCRIPT_URL}"]`);
    if (existing) {
      existing.addEventListener("load", () => resolve());
      existing.addEventListener("error", () => reject(new Error("Turnstile script load error")));
      return;
    }
    const s = document.createElement("script");
    s.src = SCRIPT_URL;
    s.async = true;
    s.defer = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error("Turnstile script load error"));
    document.head.appendChild(s);
  });
  return scriptLoadPromise;
}

// ---------- Site key hook ----------

let cachedSiteKey: string | null = null;
let siteKeyPromise: Promise<string> | null = null;

function fetchSiteKey(): Promise<string> {
  if (cachedSiteKey !== null) return Promise.resolve(cachedSiteKey);
  if (siteKeyPromise) return siteKeyPromise;
  siteKeyPromise = axios
    .get<{ turnstileSiteKey: string }>("/admin/auth/config")
    .then((r) => {
      cachedSiteKey = r.data?.turnstileSiteKey ?? "";
      return cachedSiteKey;
    })
    .catch((e) => {
      siteKeyPromise = null; // allow retry
      throw e;
    });
  return siteKeyPromise;
}

export function useTurnstileSiteKey(): { siteKey: string | null; error: Error | null } {
  const [siteKey, setSiteKey] = React.useState<string | null>(cachedSiteKey);
  const [error, setError] = React.useState<Error | null>(null);

  React.useEffect(() => {
    if (siteKey) return;
    let cancelled = false;
    fetchSiteKey()
      .then((key) => { if (!cancelled) setSiteKey(key); })
      .catch((e) => { if (!cancelled) setError(e instanceof Error ? e : new Error(String(e))); });
    return () => { cancelled = true; };
  }, [siteKey]);

  return { siteKey, error };
}

// ---------- Widget component ----------

export interface TurnstileHandle {
  reset: () => void;
}

interface TurnstileProps {
  siteKey: string;
  onVerify: (token: string) => void;
  onExpire?: () => void;
  onError?: () => void;
  theme?: "light" | "dark" | "auto";
}

const Turnstile = React.forwardRef<TurnstileHandle, TurnstileProps>(function Turnstile(
  { siteKey, onVerify, onExpire, onError, theme = "auto" },
  ref,
) {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const widgetIdRef = React.useRef<string | null>(null);

  // Keep callbacks current without remounting the widget on every parent render.
  const cbRef = React.useRef({ onVerify, onExpire, onError });
  cbRef.current = { onVerify, onExpire, onError };

  React.useEffect(() => {
    let cancelled = false;
    loadTurnstileScript()
      .then(() => {
        if (cancelled || !containerRef.current || !window.turnstile) return;
        widgetIdRef.current = window.turnstile.render(containerRef.current, {
          sitekey: siteKey,
          theme,
          callback: (token: string) => cbRef.current.onVerify(token),
          "expired-callback": () => cbRef.current.onExpire?.(),
          "error-callback": () => cbRef.current.onError?.(),
        });
      })
      .catch(() => {
        if (!cancelled) cbRef.current.onError?.();
      });

    return () => {
      cancelled = true;
      const id = widgetIdRef.current;
      widgetIdRef.current = null;
      if (id && window.turnstile) {
        try { window.turnstile.remove(id); } catch { /* ignore */ }
      }
    };
  }, [siteKey, theme]);

  React.useImperativeHandle(ref, () => ({
    reset: () => {
      const id = widgetIdRef.current;
      if (id && window.turnstile) {
        try { window.turnstile.reset(id); } catch { /* ignore */ }
      }
    },
  }));

  return <div ref={containerRef} />;
});

export default Turnstile;
