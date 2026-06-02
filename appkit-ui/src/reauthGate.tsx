// useReauthGate is the shared "verify your identity" form state used
// by sensitive operations: TOTP setup, TOTP disable, passkey delete.
// The server accepts EITHER { password } or { code } in the body of
// these endpoints — useReauthGate decides which path the UI shows
// (password input vs "email me a code" + 6-digit OTP) based on
// whether the user has a password set, and exposes the body the
// caller should submit.
//
// A user signed up via OAuth / magic-link / passkey-only has NO
// password, so falling back to the email-OTP path is the only viable
// flow for them — without it the modal would 401 forever with no
// UX hint that the alternative exists. The server deliberately
// doesn't disclose has-password state, so the disclosure has to
// come from UI ergonomics: offer the email-code path up front.

import * as React from "react";
import type { AxiosInstance, AxiosRequestConfig } from "axios";

export type ReauthGateOptions = {
  /**
   * The app's primary auth method. Decides whether the password
   * path is offered at all — for "code" or "none" apps the
   * password input is hidden even if the user happens to have one.
   * Undefined defaults to "password" for back-compat with older
   * bootstrap configs.
   */
  primaryAuthMethod: "password" | "code" | "none" | undefined;
  /**
   * Whether the user has a password set on their account. Combined
   * with primaryAuthMethod to decide if the password path is viable.
   */
  hasPassword: boolean;
  /**
   * User's email — used in the "we'll email a code to ___" copy and
   * as the recipient when hitting /auth/forgot-password.
   */
  userEmail: string | undefined;
  /**
   * Workspace-scoped base URL (e.g. https://app.manyrows.com/x/acme).
   * The hook hits ${workspaceBaseUrl}/auth/forgot-password to issue
   * the OTP.
   */
  workspaceBaseUrl: string;
  /**
   * axios instance to use for the forgot-password request. Caller
   * passes their authed axios so the hook stays mode-agnostic.
   */
  axios: AxiosInstance;
  /**
   * Standard {headers: ...} config block applied to the request.
   */
  axiosConfig: AxiosRequestConfig;
  /**
   * Caller's error setter — wired to whatever error state the
   * surrounding form already renders (totpError, passkeyError, etc.).
   */
  setError: (msg: string | null) => void;
};

export type ReauthGate = {
  /**
   * True when the password path should be offered (and the email-OTP
   * path hidden). False means email-OTP is the only viable flow.
   */
  usePasswordPath: boolean;
  pw: string;
  setPw: (v: string) => void;
  code: string;
  setCode: (v: string) => void;
  codeSending: boolean;
  codeRequested: boolean;
  /**
   * Hits ${workspaceBaseUrl}/auth/forgot-password to email the user a
   * 6-digit OTP. No-op when codeSending or userEmail is missing.
   */
  requestCode: () => Promise<void>;
  /**
   * Whether the gate has enough input to submit. Caller uses this
   * to enable/disable the Continue button.
   */
  ready: boolean;
  /**
   * Returns the body to submit to the sensitive-op endpoint, or
   * null when ready is false. Shape: { password } when on the
   * password path, { code } when on the OTP path.
   */
  body: () => { password?: string; code?: string } | null;
  /**
   * Clears all gate state. Call on cancel and after a successful
   * submit so a stale password doesn't sit in memory between ops.
   */
  reset: () => void;
};

export function useReauthGate(opts: ReauthGateOptions): ReauthGate {
  const { primaryAuthMethod, hasPassword, userEmail, workspaceBaseUrl, axios: ax, axiosConfig, setError } = opts;

  const [pw, setPw] = React.useState("");
  const [code, setCode] = React.useState("");
  const [codeSending, setCodeSending] = React.useState(false);
  const [codeRequested, setCodeRequested] = React.useState(false);

  // Password path is viable only when the app's primary auth method
  // accepts a password AND the user actually has one set. Default to
  // "password path" when primaryAuthMethod is undefined so older
  // bootstrap configs keep working.
  const usePasswordPath = (!primaryAuthMethod || primaryAuthMethod === "password") && hasPassword;

  const requestCode = async () => {
    if (!userEmail || codeSending) return;
    setCodeSending(true);
    setError(null);
    try {
      await ax.post(`${workspaceBaseUrl}/auth/forgot-password`, { email: userEmail }, axiosConfig);
      setCodeRequested(true);
    } catch (err: unknown) {
      const fallback = "Failed to send code";
      const e = err as { response?: { data?: { message?: string; error?: string } | string } } | undefined;
      const d = e?.response?.data;
      const msg = typeof d === "string"
        ? d
        : (d?.message ?? d?.error ?? fallback);
      setError(msg || fallback);
    } finally {
      setCodeSending(false);
    }
  };

  const ready = usePasswordPath
    ? pw.trim().length > 0
    : codeRequested && code.trim().length === 6;

  const body = (): { password?: string; code?: string } | null => {
    if (!ready) return null;
    return usePasswordPath ? { password: pw } : { code: code.trim() };
  };

  const reset = () => {
    setPw("");
    setCode("");
    setCodeRequested(false);
  };

  return {
    usePasswordPath,
    pw, setPw,
    code, setCode,
    codeSending, codeRequested,
    requestCode,
    ready, body, reset,
  };
}

export type ReauthGateFieldsProps = {
  gate: ReauthGate;
  loading: boolean;
  userEmail: string | undefined;
  /**
   * Style props passed through from the caller — keeps the gate
   * agnostic to its surrounding visual system (Profile.tsx,
   * UserButton.tsx, and AppKit.tsx each style buttons + inputs
   * differently).
   *
   * Pass `inputStyle` / `buttonStyle` for inline-style designs
   * (Profile.tsx), or `inputClassName` / `buttonClassName` for
   * class-based designs (UserButton.tsx, AppKit.tsx). Both can
   * coexist; className wins for layout, style props apply on top.
   */
  inputStyle?: React.CSSProperties;
  buttonStyle?: React.CSSProperties;
  inputClassName?: string;
  buttonClassName?: string;
  /**
   * Optional Spinner component the caller's UI already ships.
   * Falls back to the text "…" so a missing spinner doesn't break
   * the layout.
   */
  Spinner?: React.ComponentType<{ size?: number }>;
};

/**
 * ReauthGateFields renders the password input OR the email-OTP flow
 * based on which path the gate decided is viable. Stateless — caller
 * owns the gate. Reused across Profile.tsx, UserButton.tsx, and
 * AppKit.tsx (and any future sensitive-op confirmation).
 */
export function ReauthGateFields({ gate, loading, userEmail, inputStyle, buttonStyle, inputClassName, buttonClassName, Spinner }: ReauthGateFieldsProps): React.ReactElement {
  const secondary: React.CSSProperties = { fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0, lineHeight: 1.5 };
  const spin = (size: number) => Spinner ? <Spinner size={size} /> : <>…</>;

  if (gate.usePasswordPath) {
    return (
      <input
        className={inputClassName}
        style={inputStyle}
        type="password"
        placeholder="Enter your password to confirm"
        value={gate.pw}
        onChange={(e) => gate.setPw(e.target.value)}
        disabled={loading}
        autoComplete="current-password"
      />
    );
  }
  if (!gate.codeRequested) {
    return (
      <>
        <p style={secondary}>
          We'll email a verification code to <strong>{userEmail || "your address"}</strong> to confirm.
        </p>
        <button
          type="button"
          className={buttonClassName}
          onClick={gate.requestCode}
          disabled={gate.codeSending}
          style={buttonStyle ? { ...buttonStyle, opacity: gate.codeSending ? 0.5 : 1 } : undefined}
        >
          {gate.codeSending ? spin(14) : "Email me a code"}
        </button>
      </>
    );
  }
  return (
    <>
      <p style={secondary}>
        A 6-digit code was sent to <strong>{userEmail}</strong>.
      </p>
      <input
        className={inputClassName}
        style={inputStyle ? { ...inputStyle, textAlign: "center", letterSpacing: 4, fontSize: 18 } : { textAlign: "center", letterSpacing: "0.5em" }}
        type="text"
        placeholder="000000"
        value={gate.code}
        onChange={(e) => gate.setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
        maxLength={6}
        disabled={loading}
      />
    </>
  );
}
