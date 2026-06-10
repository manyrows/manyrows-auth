import * as React from "react";
import { useAuthedAxios } from "./AppKit";
import QRCode from "qrcode";
import Spinner from "./Spinner";
import Icon from "./Icon";
import { extractApiErrorMessage } from "./errors";
import { useReauthGate, ReauthGateFields } from "./reauthGate";
import {
  decodeCreationOptions,
  encodeAttestationResponse,
  isPasskeySupported,
} from "./webauthnUtil";

// Local QR generator — never sends the TOTP secret off-device.
function QRCodeImg({ data, size }: { data: string; size: number }) {
  const [src, setSrc] = React.useState<string | null>(null);
  React.useEffect(() => {
    let cancelled = false;
    QRCode.toDataURL(data, { width: size, margin: 1 }).then((url) => {
      if (!cancelled) setSrc(url);
    });
    return () => { cancelled = true; };
  }, [data, size]);
  if (!src) return null;
  return <img src={src} alt="TOTP QR Code" width={size} height={size} style={{ borderRadius: 8 }} />;
}

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "10px 12px",
  fontSize: 14,
  border: "1px solid var(--ak-color-border, #d1d5db)",
  borderRadius: "var(--ak-radius-md, 8px)",
  background: "var(--ak-color-card-bg, #fff)",
  color: "var(--ak-color-text, #111)",
  outline: "none",
  boxSizing: "border-box",
};

const btnStyle: React.CSSProperties = {
  width: "100%",
  padding: "10px 16px",
  fontSize: 14,
  fontWeight: 600,
  border: "none",
  borderRadius: "var(--ak-radius-md, 8px)",
  background: "var(--ak-color-primary, #6366f1)",
  color: "#fff",
  cursor: "pointer",
  opacity: 1,
};

const btnOutlinedStyle: React.CSSProperties = {
  padding: "8px 16px",
  fontSize: 13,
  fontWeight: 500,
  border: "1px solid var(--ak-color-border, #d1d5db)",
  borderRadius: "var(--ak-radius-md, 8px)",
  background: "transparent",
  color: "var(--ak-color-text, #111)",
  cursor: "pointer",
};

const alertBase: React.CSSProperties = {
  padding: "10px 14px",
  borderRadius: "var(--ak-radius-md, 8px)",
  fontSize: 13,
  lineHeight: 1.5,
};

const alertError: React.CSSProperties = {
  ...alertBase,
  background: "#fef2f2",
  color: "#991b1b",
  border: "1px solid #fecaca",
};

const alertSuccess: React.CSSProperties = {
  ...alertBase,
  background: "#f0fdf4",
  color: "#166534",
  border: "1px solid #bbf7d0",
};

const alertWarning: React.CSSProperties = {
  ...alertBase,
  background: "#fffbeb",
  color: "#92400e",
  border: "1px solid #fde68a",
};

function parseBrowser(ua?: string): string {
  if (!ua) return "Unknown device";
  if (ua.includes("Firefox")) return "Firefox";
  if (ua.includes("Edg/")) return "Edge";
  if (ua.includes("Chrome")) return "Chrome";
  if (ua.includes("Safari")) return "Safari";
  if (ua.includes("Opera") || ua.includes("OPR/")) return "Opera";
  return ua.length > 40 ? ua.slice(0, 40) + "..." : ua;
}

function formatRelative(iso: string): string {
  const d = new Date(iso);
  const now = Date.now();
  const diffMs = now - d.getTime();
  const mins = Math.floor(diffMs / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

interface ProfileProps {
  workspaceBaseUrl: string;
  jwtToken: string | null;
  user?: { id: string; email: string } | null;
  onBack?: () => void;
  hideBranding?: boolean;
  passkeyEnabled?: boolean;
  /**
   * Whether the "Delete account" button is shown. Mirrors the per-app
   * `allow_account_deletion` flag in admin (General tab). Defaults to
   * true so apps that haven't been touched since the flag rolled out
   * keep their existing UI. The server enforces the same flag and
   * returns 403 if a stale client tries to call /a/me/delete.
   */
  allowAccountDeletion?: boolean;
  /**
   * Whether the "Change email" block is shown. Mirrors the per-app
   * `allow_email_change` flag in admin (General tab). Defaults to
   * true. Server enforces too: /a/me/request-email-change and
   * /a/me/verify-email-change return 403 when the flag is off.
   */
  allowEmailChange?: boolean;
  /**
   * Triggers AppKit's logout flow. Wired from <AppKit>'s context
   * value in AppKit.tsx — the same path the host's
   * `appKit.logout()` API call uses.
   */
  onLogout?: () => void | Promise<void>;
  /**
   * App's primary auth method. Used to decide whether the "Disable
   * 2FA" confirm step asks for the password (when password mode is
   * active AND the user has one) or sends an email-OTP instead.
   */
  primaryAuthMethod?: "password" | "code" | "none";
  /**
   * Whether any OAuth provider (Google / Apple / Microsoft / GitHub)
   * is enabled for the app. Controls visibility of the "Connected"
   * tab — there's nothing to manage if the app can't link OAuth
   * identities in the first place. Defaults to true for back-compat
   * with hosts that don't pass it yet.
   */
  oauthEnabled?: boolean;
}

type Tab = "profile" | "password" | "security" | "sessions" | "connected";

const PROVIDER_LABEL: Record<string, string> = {
  google: "Google",
  apple: "Apple",
  microsoft: "Microsoft",
  github: "GitHub",
  kakao: "Kakao",
  naver: "Naver",
};

export default function Profile({ workspaceBaseUrl, jwtToken, user, onBack, hideBranding, passkeyEnabled, allowAccountDeletion = true, allowEmailChange = true, onLogout, primaryAuthMethod, oauthEnabled = true }: ProfileProps) {
  // authedAxios attaches the latest access token per-request via its
  // own request interceptor (see AppKit.tsx). No need to maintain a
  // jwtToken-keyed Authorization header object here — that's the trap
  // that left mid-flight calls holding stale bearers after a refresh.
  // authHeaders intentionally empty — don't override withCredentials
  // here, authedAxios's request interceptor sets it from the current
  // transport mode (cookie or bearer).
  const authedAxios = useAuthedAxios();
  const authHeaders = React.useMemo(
    () => ({}),
    [],
  );

  const [tab, setTab] = React.useState<Tab>("profile");

  // Password
  const [currentPw, setCurrentPw] = React.useState("");
  const [newPw, setNewPw] = React.useState("");
  const [confirmPw, setConfirmPw] = React.useState("");
  const [pwLoading, setPwLoading] = React.useState(false);
  const [pwError, setPwError] = React.useState<string | null>(null);
  const [pwSuccess, setPwSuccess] = React.useState(false);
  const [hasPassword, setHasPassword] = React.useState(false);

  // Passkeys
  type PasskeyItem = {
    id: string;
    name?: string;
    transports: string[];
    aaguid?: string;
    authenticatorName?: string;
    backupEligible: boolean;
    backupState: boolean;
    createdAt: string;
    lastUsedAt?: string;
  };
  const [passkeys, setPasskeys] = React.useState<PasskeyItem[]>([]);
  const [passkeysLoading, setPasskeysLoading] = React.useState(false);
  const [passkeyError, setPasskeyError] = React.useState<string | null>(null);
  const [passkeyAdding, setPasskeyAdding] = React.useState(false);
  const [passkeyDeletingId, setPasskeyDeletingId] = React.useState<string | null>(null);
  const [passkeyRenamingId, setPasskeyRenamingId] = React.useState<string | null>(null);
  // Per-row "delete confirmation" state. When the user clicks the
  // trash button we move into a re-auth confirm form for that row —
  // backend requires { password } or { code } so a stolen access
  // token alone can't wipe every passkey on an account.
  const [passkeyConfirmingId, setPasskeyConfirmingId] = React.useState<string | null>(null);
  const [passkeyRenameValue, setPasskeyRenameValue] = React.useState("");

  const passkeysAvailable = !!passkeyEnabled && isPasskeySupported();

  const loadPasskeys = React.useCallback(async () => {
    if (!passkeysAvailable) return;
    setPasskeysLoading(true);
    setPasskeyError(null);
    try {
      const res = await authedAxios.get(`${workspaceBaseUrl}/a/passkeys`, authHeaders);
      setPasskeys(res.data?.passkeys ?? []);
    } catch (e: any) {
      setPasskeyError(extractApiErrorMessage(e, "Could not load passkeys"));
    } finally {
      setPasskeysLoading(false);
    }
  }, [passkeysAvailable, jwtToken, workspaceBaseUrl, authHeaders]);

  React.useEffect(() => {
    if (tab === "security" && passkeysAvailable) void loadPasskeys();
  }, [tab, passkeysAvailable, loadPasskeys]);

  const onAddPasskey = async () => {
    if (!passkeysAvailable || passkeyAdding) return;
    setPasskeyAdding(true);
    setPasskeyError(null);
    try {
      const beginRes = await authedAxios.post(`${workspaceBaseUrl}/a/passkey/register/begin`, {}, authHeaders);
      const { challengeId, publicKeyOptions } = beginRes.data;
      if (!challengeId || !publicKeyOptions) throw new Error("Invalid passkey response");
      const opts = decodeCreationOptions(publicKeyOptions);
      const credential = (await navigator.credentials.create({ publicKey: opts })) as PublicKeyCredential | null;
      if (!credential) throw new Error("Passkey creation cancelled");
      const defaultName = (() => {
        const ua = navigator.userAgent;
        if (/iPhone|iPad/.test(ua)) return "iPhone passkey";
        if (/Macintosh/.test(ua)) return "Mac passkey";
        if (/Android/.test(ua)) return "Android passkey";
        if (/Windows/.test(ua)) return "Windows passkey";
        return null;
      })();
      await authedAxios.post(
        `${workspaceBaseUrl}/a/passkey/register/finish`,
        { challengeId, name: defaultName, response: encodeAttestationResponse(credential) },
        authHeaders,
      );
      await loadPasskeys();
    } catch (e: any) {
      if (e?.name === "NotAllowedError" || e?.name === "AbortError") {
        setPasskeyError("Passkey creation cancelled");
      } else {
        setPasskeyError(extractApiErrorMessage(e, "Could not add passkey"));
      }
    } finally {
      setPasskeyAdding(false);
    }
  };

  const onDeletePasskey = async (id: string, body: { password?: string; code?: string }) => {
    setPasskeyDeletingId(id);
    setPasskeyError(null);
    try {
      // DELETE-with-body is unusual but the backend reads it on this
      // endpoint (see passkeyHandler.go WorkspaceDeletePasskey). axios
      // accepts a `data` field on its config object for DELETE bodies;
      // most fetch examples don't show this shape, hence the comment.
      await authedAxios.delete(`${workspaceBaseUrl}/a/passkeys/${encodeURIComponent(id)}`, { ...authHeaders, data: body });
      setPasskeys((ps) => ps.filter((p) => p.id !== id));
      setPasskeyConfirmingId(null);
      passkeyGate.reset();
    } catch (e: any) {
      setPasskeyError(extractApiErrorMessage(e, "Could not delete passkey"));
    } finally {
      setPasskeyDeletingId(null);
    }
  };

  const onRenamePasskey = async (id: string) => {
    const name = passkeyRenameValue.trim();
    setPasskeyError(null);
    try {
      await authedAxios.patch(`${workspaceBaseUrl}/a/passkeys/${encodeURIComponent(id)}`, { name: name || null }, authHeaders);
      setPasskeys((ps) => ps.map((p) => (p.id === id ? { ...p, name: name || undefined } : p)));
      setPasskeyRenamingId(null);
      setPasskeyRenameValue("");
    } catch (e: any) {
      setPasskeyError(extractApiErrorMessage(e, "Could not rename passkey"));
    }
  };

  // TOTP
  const [totpEnabled, setTotpEnabled] = React.useState(false);
  const [totpUri, setTotpUri] = React.useState("");
  const [totpCode, setTotpCode] = React.useState("");
  const [totpLoading, setTotpLoading] = React.useState(false);
  const [totpError, setTotpError] = React.useState<string | null>(null);
  const [totpStep, setTotpStep] = React.useState<"idle" | "confirmSetup" | "scan" | "verify" | "backup" | "confirmDisable">("idle");
  const [backupCodes, setBackupCodes] = React.useState<string[]>([]);

  // User fields
  const [fields, setFields] = React.useState<{ key: string; type: string; label: string; value: string }[]>([]);
  const [fieldEdits, setFieldEdits] = React.useState<Record<string, string>>({});
  const [fieldsEditing, setFieldsEditing] = React.useState(false);

  // Load user info — once per authenticated mount. Token rotations
  // (post-interceptor refresh) change jwtToken's value but the
  // underlying user data doesn't, so re-fetching every time the
  // bearer rotates is wasted bandwidth. /me runs first; /fields only
  // fires after /me resolves successfully — if /me 401s and the
  // session is gone, there's no point asking for /fields.
  const profileFetchedRef = React.useRef(false);
  React.useEffect(() => {
    // Don't gate on jwtToken — it's empty in cookie mode where auth
    // is cookie-borne, and the upstream gate already ensures Profile
    // only renders for logged-in users. workspaceBaseUrl is the only
    // real prerequisite (we need a URL to call).
    if (!workspaceBaseUrl) {
      profileFetchedRef.current = false;
      return;
    }
    if (profileFetchedRef.current) return;
    profileFetchedRef.current = true;

    (async () => {
      try {
        const meRes = await authedAxios.get(`${workspaceBaseUrl}/a/me`, authHeaders);
        setHasPassword(!!meRes.data?.user?.passwordSetAt);
        setTotpEnabled(!!meRes.data?.user?.totpEnabled);
      } catch {
        return;
      }
      try {
        const fieldsRes = await authedAxios.get(`${workspaceBaseUrl}/a/me/fields`, authHeaders);
        const items = fieldsRes.data?.fields ?? [];
        setFields(items);
        const edits: Record<string, string> = {};
        for (const f of items) {
          edits[f.key] = f.value != null ? (typeof f.value === "string" ? f.value : JSON.stringify(f.value)) : "";
        }
        setFieldEdits(edits);
      } catch {
        // ignore
      }
    })();
  }, [jwtToken, workspaceBaseUrl, authHeaders]);

  // Profile tab is always shown (it carries email + any user fields).
  // The tab order is fixed: Profile | Password | Security | Sessions.

  // Sessions
  type SessionItem = { id: string; createdAt: string; lastSeenAt: string; userAgent?: string; ip?: string; current: boolean };
  const [sessions, setSessions] = React.useState<SessionItem[]>([]);
  const [sessionsLoading, setSessionsLoading] = React.useState(false);
  const [sessionsError, setSessionsError] = React.useState<string | null>(null);
  const [revokingId, setRevokingId] = React.useState<string | null>(null);

  const loadSessions = React.useCallback(async () => {
    setSessionsLoading(true);
    setSessionsError(null);
    try {
      const res = await authedAxios.get(`${workspaceBaseUrl}/a/me/sessions`, authHeaders);
      setSessions(res.data?.sessions ?? []);
    } catch {
      setSessionsError("Failed to load sessions");
    } finally {
      setSessionsLoading(false);
    }
  }, [workspaceBaseUrl, authHeaders]);

  React.useEffect(() => {
    if (tab === "sessions") {
      void loadSessions();
    } else {
      setConfirmingRevokeAll(false);
    }
  }, [tab]);

  // Connected accounts (Google / Apple / Microsoft / GitHub)
  type IdentityItem = { provider: string; providerEmail?: string; createdAt: string; lastLoginAt: string };
  const [identities, setIdentities] = React.useState<IdentityItem[]>([]);
  const [identitiesLoading, setIdentitiesLoading] = React.useState(false);
  const [identitiesError, setIdentitiesError] = React.useState<string | null>(null);
  const [disconnectingProvider, setDisconnectingProvider] = React.useState<string | null>(null);

  const loadIdentities = React.useCallback(async () => {
    setIdentitiesLoading(true);
    setIdentitiesError(null);
    try {
      const res = await authedAxios.get(`${workspaceBaseUrl}/a/me/identities`, authHeaders);
      setIdentities(res.data?.identities ?? []);
    } catch {
      setIdentitiesError("Failed to load connected accounts");
    } finally {
      setIdentitiesLoading(false);
    }
  }, [workspaceBaseUrl, authHeaders]);

  React.useEffect(() => {
    if (tab === "connected") void loadIdentities();
  }, [tab]);

  const disconnectIdentity = async (provider: string) => {
    setDisconnectingProvider(provider);
    try {
      // NB: send the provider key verbatim. External-IdP keys are
      // "idp:<uuid>" (a colon), and the server's router does NOT
      // percent-decode path params — encodeURIComponent here would turn
      // the colon into %3A and silently fail to match the stored row.
      await authedAxios.delete(`${workspaceBaseUrl}/a/me/identities/${provider}`, authHeaders);
      setIdentities((prev) => prev.filter((i) => i.provider !== provider));
    } catch {
      setIdentitiesError("Failed to disconnect account");
    } finally {
      setDisconnectingProvider(null);
    }
  };

  const revokeSession = async (sessionId: string) => {
    setRevokingId(sessionId);
    try {
      await authedAxios.delete(`${workspaceBaseUrl}/a/me/sessions/${sessionId}`, authHeaders);
      setSessions((prev) => prev.filter((s) => s.id !== sessionId));
    } catch {
      setSessionsError("Failed to revoke session");
    } finally {
      setRevokingId(null);
    }
  };

  const [revokingOthers, setRevokingOthers] = React.useState(false);
  const [confirmingRevokeAll, setConfirmingRevokeAll] = React.useState(false);

  const revokeOtherSessions = async () => {
    setRevokingOthers(true);
    setConfirmingRevokeAll(false);
    try {
      await authedAxios.delete(`${workspaceBaseUrl}/a/me/sessions`, authHeaders);
      await loadSessions();
    } catch {
      setSessionsError("Failed to sign out other devices");
    } finally {
      setRevokingOthers(false);
    }
  };

  // Email change
  const [emailStep, setEmailStep] = React.useState<"idle" | "form" | "verify" | "done">("idle");
  const [emailPw, setEmailPw] = React.useState("");
  const [emailNew, setEmailNew] = React.useState("");
  const [emailOldCode, setEmailOldCode] = React.useState("");
  const [emailNewCode, setEmailNewCode] = React.useState("");
  const [emailLoading, setEmailLoading] = React.useState(false);
  const [emailError, setEmailError] = React.useState<string | null>(null);
  const [emailSuccess, setEmailSuccess] = React.useState<string | null>(null);
  const [displayEmail, setDisplayEmail] = React.useState(user?.email || "");

  React.useEffect(() => {
    setDisplayEmail(user?.email || "");
  }, [user?.email]);

  const requestEmailChange = async () => {
    if (!emailPw.trim() || !emailNew.trim()) return;
    setEmailLoading(true);
    setEmailError(null);
    try {
      await authedAxios.post(`${workspaceBaseUrl}/a/me/request-email-change`, { password: emailPw, newEmail: emailNew }, authHeaders);
      setEmailStep("verify");
    } catch (err: any) {
      setEmailError(extractApiErrorMessage(err, "Failed to request email change"));
    } finally {
      setEmailLoading(false);
    }
  };

  const verifyEmailChange = async () => {
    if (!emailOldCode.trim() || !emailNewCode.trim()) return;
    setEmailLoading(true);
    setEmailError(null);
    try {
      const res = await authedAxios.post(
        `${workspaceBaseUrl}/a/me/verify-email-change`,
        { oldCode: emailOldCode.trim(), newCode: emailNewCode.trim() },
        authHeaders,
      );
      const newEmail = res.data?.email || emailNew;
      setDisplayEmail(newEmail);
      setEmailSuccess("Email changed successfully");
      setEmailStep("done");
      setEmailPw("");
      setEmailNew("");
      setEmailOldCode("");
      setEmailNewCode("");
      setTimeout(() => { setEmailSuccess(null); setEmailStep("idle"); }, 4000);
    } catch (err: any) {
      setEmailError(extractApiErrorMessage(err, "Invalid code"));
    } finally {
      setEmailLoading(false);
    }
  };

  // Delete account
  const [deleteStep, setDeleteStep] = React.useState<"idle" | "confirm">("idle");
  const [deletePw, setDeletePw] = React.useState("");
  const [deleteLoading, setDeleteLoading] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState<string | null>(null);

  const deleteAccount = async () => {
    setDeleteLoading(true);
    setDeleteError(null);
    try {
      await authedAxios.post(`${workspaceBaseUrl}/a/me/delete`, { password: deletePw }, authHeaders);
      // Account deleted — trigger logout
      if (onBack) onBack();
      window.location.reload();
    } catch (err: any) {
      setDeleteError(extractApiErrorMessage(err, "Failed to delete account"));
    } finally {
      setDeleteLoading(false);
    }
  };

  // Initial password set (no current password) flow:
  // for users who signed up via OAuth, setting a password without
  // verifying email control would let a stolen access token install
  // a persistent backdoor. We require an email-OTP step — the same
  // /auth/forgot-password + /auth/reset-password endpoints used for
  // password reset, but driven from inside the profile dialog.
  const [setPwStep, setSetPwStep] = React.useState<"idle" | "code">("idle");
  const [setPwCode, setSetPwCode] = React.useState("");
  const [setPwSending, setSetPwSending] = React.useState(false);

  const requestSetPasswordCode = async () => {
    if (!user?.email || setPwSending) return;
    setSetPwSending(true);
    setPwError(null);
    try {
      await authedAxios.post(`${workspaceBaseUrl}/auth/forgot-password`, {
        email: user.email,
      }, authHeaders);
      setSetPwStep("code");
    } catch (err: any) {
      setPwError(extractApiErrorMessage(err, "Failed to send code"));
    } finally {
      setSetPwSending(false);
    }
  };

  const confirmSetPasswordWithCode = async () => {
    if (!user?.email) return;
    if (!setPwCode.trim() || setPwCode.trim().length !== 6) {
      setPwError("Enter the 6-digit code from your email");
      return;
    }
    if (newPw.trim().length < 10 || newPw !== confirmPw) {
      setPwError(newPw !== confirmPw ? "Passwords do not match" : "Password must be at least 10 characters");
      return;
    }
    setPwLoading(true);
    setPwError(null);
    try {
      await authedAxios.post(`${workspaceBaseUrl}/auth/reset-password`, {
        email: user.email,
        code: setPwCode.trim(),
        newPassword: newPw,
        logoutAll: false, // keep this session alive
      }, authHeaders);
      setPwSuccess(true);
      setHasPassword(true);
      setSetPwStep("idle");
      setSetPwCode("");
      setNewPw("");
      setConfirmPw("");
      setTimeout(() => setPwSuccess(false), 3000);
    } catch (err: any) {
      setPwError(extractApiErrorMessage(err, "Failed to set password"));
    } finally {
      setPwLoading(false);
    }
  };

  // Password
  const savePassword = async () => {
    if (!newPw.trim() || newPw !== confirmPw) {
      setPwError(newPw !== confirmPw ? "Passwords do not match" : "Password is required");
      return;
    }
    if (hasPassword && !currentPw.trim()) {
      setPwError("Current password is required");
      return;
    }
    setPwLoading(true);
    setPwError(null);
    try {
      await authedAxios.post(`${workspaceBaseUrl}/a/set-password`, {
        password: newPw,
        ...(hasPassword ? { currentPassword: currentPw } : {}),
      }, authHeaders);
      setPwSuccess(true);
      setHasPassword(true);
      setCurrentPw("");
      setNewPw("");
      setConfirmPw("");
      setTimeout(() => setPwSuccess(false), 3000);
    } catch (err: any) {
      setPwError(extractApiErrorMessage(err, "Failed to set password"));
    } finally {
      setPwLoading(false);
    }
  };

  // Sensitive-operation re-auth gates (TOTP setup, TOTP disable,
  // passkey delete). The server-side helper requireSensitivePasswordOrCodeReauth
  // accepts EITHER { password } or { code } — useReauthGate handles
  // the matching UI flow. See reauthGate.tsx for the contract.
  const gateOptions = {
    primaryAuthMethod,
    hasPassword,
    userEmail: user?.email,
    workspaceBaseUrl,
    axios: authedAxios,
    axiosConfig: authHeaders,
  };
  const setupGate = useReauthGate({ ...gateOptions, setError: setTotpError });
  const passkeyGate = useReauthGate({ ...gateOptions, setError: setPasskeyError });

  const startTotpSetup = async () => {
    const body = setupGate.body();
    if (!body) {
      setTotpError(setupGate.usePasswordPath ? "Password is required to start setup" : "Enter the 6-digit code from your email");
      return;
    }
    setTotpLoading(true);
    setTotpError(null);
    try {
      const res = await authedAxios.post(`${workspaceBaseUrl}/a/totp/setup`, body, authHeaders);
      setTotpUri(res.data.uri);
      setTotpStep("scan");
      setupGate.reset();
    } catch (err: any) {
      setTotpError(extractApiErrorMessage(err, "Failed to start setup"));
    } finally {
      setTotpLoading(false);
    }
  };

  const verifyTotp = async () => {
    if (!totpCode.trim()) return;
    setTotpLoading(true);
    setTotpError(null);
    try {
      const res = await authedAxios.post(`${workspaceBaseUrl}/a/totp/enable`, { code: totpCode.trim() }, authHeaders);
      setBackupCodes(res.data.backupCodes || []);
      setTotpStep("backup");
      setTotpEnabled(true);
    } catch (err: any) {
      setTotpError(extractApiErrorMessage(err, "Invalid code"));
    } finally {
      setTotpLoading(false);
    }
  };

  const disableGate = useReauthGate({ ...gateOptions, setError: setTotpError });

  const disableTotp = async () => {
    const body = disableGate.body();
    if (!body) {
      setTotpError(disableGate.usePasswordPath ? "Password is required to disable 2FA" : "Enter the 6-digit code from your email");
      return;
    }
    setTotpLoading(true);
    setTotpError(null);
    try {
      await authedAxios.post(`${workspaceBaseUrl}/a/totp/disable`, body, authHeaders);
      setTotpEnabled(false);
      setTotpStep("idle");
      disableGate.reset();
    } catch (err: any) {
      setTotpError(extractApiErrorMessage(err, "Failed to disable"));
    } finally {
      setTotpLoading(false);
    }
  };

  // Fields
  const [fieldsSaving, setFieldsSaving] = React.useState(false);
  const [fieldsSuccess, setFieldsSuccess] = React.useState(false);
  const saveAllFields = async () => {
    setFieldsSaving(true);
    try {
      const patch: Record<string, any> = {};
      for (const f of fields) {
        patch[f.key] = f.type === "bool" ? (fieldEdits[f.key] === "true") : (fieldEdits[f.key] || "");
      }
      await authedAxios.patch(`${workspaceBaseUrl}/a/me/fields`, patch, authHeaders);
      setFieldsEditing(false);
      setFieldsSuccess(true);
      setTimeout(() => setFieldsSuccess(false), 3000);
    } catch { /* silent */ } finally {
      setFieldsSaving(false);
    }
  };

  // Hide the Password tab + Change Email block when the app's
  // primary auth method isn't password — there's no email/password
  // form on the login screen, so a password serves no purpose, and
  // Change Email needs password confirmation server-side. Default
  // to true when primaryAuthMethod is undefined (older bootstrap
  // config) so existing apps keep working unchanged.
  const showPasswordTab = !primaryAuthMethod || primaryAuthMethod === "password";

  React.useEffect(() => {
    if (!showPasswordTab && tab === "password") setTab("profile");
  }, [showPasswordTab, tab]);

  React.useEffect(() => {
    if (!oauthEnabled && tab === "connected") setTab("profile");
  }, [oauthEnabled, tab]);

  const tabStyle = (t: Tab): React.CSSProperties => ({
    flex: 1,
    padding: "8px 16px",
    fontSize: 13,
    fontWeight: 600,
    cursor: "pointer",
    border: "none",
    background: "none",
    borderBottom: tab === t ? "2px solid var(--ak-color-primary, #6366f1)" : "2px solid transparent",
    color: tab === t ? "var(--ak-color-primary, #6366f1)" : "var(--ak-color-text-secondary, #666)",
  });

  return (
    <div style={{ maxWidth: 480, margin: "0 auto", padding: 16 }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h2 className="ak-h6" style={{ fontWeight: 700, margin: 0 }}>Profile</h2>
        {onBack && (
          <button
            onClick={onBack}
            style={{
              background: "none", border: "none", cursor: "pointer", padding: 8,
              fontSize: 18, color: "var(--ak-color-text-secondary, #666)", lineHeight: 1,
            }}
            aria-label="Close"
          >
            ✕
          </button>
        )}
      </div>

      {/* Tabs — Password tab + Change Email both depend on the app
          having email/password sign-in enabled. With "code" or "none"
          mode there's no email/password form on the login screen, so a
          password serves no purpose, and Change Email needs password
          confirmation server-side. If the user happens to be on the
          Password tab when the flag changes, an effect bounces them
          back to Profile. */}
      <div style={{ display: "flex", borderBottom: "1px solid var(--ak-color-border, #e5e5e5)", marginBottom: 20 }}>
        <button style={tabStyle("profile")} onClick={() => setTab("profile")}>Profile</button>
        {showPasswordTab && (
          <button style={tabStyle("password")} onClick={() => setTab("password")}>Password</button>
        )}
        <button style={tabStyle("security")} onClick={() => setTab("security")}>Security</button>
        <button style={tabStyle("sessions")} onClick={() => setTab("sessions")}>Sessions</button>
        {oauthEnabled && (
          <button style={tabStyle("connected")} onClick={() => setTab("connected")}>Connected</button>
        )}
      </div>

      {/* Account Tab */}
      {tab === "password" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 14, fontWeight: 600 }}>{hasPassword ? "Change Password" : "Set Password"}</span>
            <span style={{ fontSize: 12, color: hasPassword ? "var(--ak-color-success, #16a34a)" : "var(--ak-color-text-secondary, #666)" }}>
              {hasPassword ? "Password is set" : "No password set"}
            </span>
          </div>

          {hasPassword ? (
            // Change-password form: requires current password as confirmation.
            // No email OTP needed — knowing the current password is the proof
            // of control.
            <form style={{ display: "flex", flexDirection: "column", gap: 10 }} onSubmit={(e) => e.preventDefault()} onKeyDown={(e) => { if (e.key === "Enter") e.preventDefault(); }}>
              <input type="text" name="username" autoComplete="username" value={user?.email || ""} readOnly style={{ display: "none" }} tabIndex={-1} />
              <input
                style={inputStyle}
                type="password"
                placeholder="Current password"
                value={currentPw}
                onChange={(e) => setCurrentPw(e.target.value)}
                disabled={pwLoading}
                autoComplete="current-password"
              />
              <input
                style={inputStyle}
                type="password"
                placeholder="New password"
                value={newPw}
                onChange={(e) => setNewPw(e.target.value)}
                disabled={pwLoading}
                autoComplete="new-password"
              />
              <input
                style={inputStyle}
                type="password"
                placeholder="Confirm password"
                value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                disabled={pwLoading}
                autoComplete="new-password"
              />
              {pwError && <div style={alertError}><span>{pwError}</span></div>}
              {pwSuccess && <div style={alertSuccess}><span>Password saved</span></div>}
              {newPw.trim().length > 0 && newPw.trim().length < 10 && (
                <span style={{ fontSize: 12, color: "var(--ak-color-error, #dc2626)" }}>Password must be at least 10 characters</span>
              )}
              {newPw.trim().length >= 10 && confirmPw.trim().length > 0 && newPw !== confirmPw && (
                <span style={{ fontSize: 12, color: "var(--ak-color-error, #dc2626)" }}>Passwords do not match</span>
              )}
              <button
                type="button"
                onClick={savePassword}
                disabled={
                  pwLoading ||
                  newPw.trim().length < 10 ||
                  newPw !== confirmPw ||
                  !currentPw.trim()
                }
                style={{ ...btnStyle, marginTop: 4, opacity: (pwLoading || newPw.trim().length < 10 || newPw !== confirmPw || !currentPw.trim()) ? 0.5 : 1 }}
              >
                {pwLoading ? <Spinner size={16} /> : "Change Password"}
              </button>
            </form>
          ) : (
            // Initial-set flow: requires an email-OTP first. Without it,
            // a stolen access token could silently install a password
            // backdoor on an OAuth-only account. The OTP is sent to the
            // user's verified email; they enter it alongside the new
            // password to complete the set.
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {setPwStep === "idle" && (
                <>
                  <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0, lineHeight: 1.5 }}>
                    To set a password, we'll first email a verification code to <strong>{user?.email || "your address"}</strong>.
                  </p>
                  {pwError && <div style={alertError}><span>{pwError}</span></div>}
                  <button
                    type="button"
                    onClick={requestSetPasswordCode}
                    disabled={setPwSending}
                    style={{ ...btnStyle, marginTop: 4, opacity: setPwSending ? 0.5 : 1 }}
                  >
                    {setPwSending ? <Spinner size={16} /> : "Email me a verification code"}
                  </button>
                </>
              )}

              {setPwStep === "code" && (
                <form style={{ display: "flex", flexDirection: "column", gap: 10 }} onSubmit={(e) => e.preventDefault()} onKeyDown={(e) => { if (e.key === "Enter") e.preventDefault(); }}>
                  <input type="text" name="username" autoComplete="username" value={user?.email || ""} readOnly style={{ display: "none" }} tabIndex={-1} />
                  <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0, lineHeight: 1.5 }}>
                    A 6-digit code was sent to <strong>{user?.email}</strong>. Enter it along with your new password.
                  </p>
                  <input
                    style={{ ...inputStyle, textAlign: "center", letterSpacing: 4, fontSize: 18 }}
                    type="text"
                    placeholder="000000"
                    value={setPwCode}
                    onChange={(e) => setSetPwCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    maxLength={6}
                    disabled={pwLoading}
                  />
                  <input
                    style={inputStyle}
                    type="password"
                    placeholder="New password"
                    value={newPw}
                    onChange={(e) => setNewPw(e.target.value)}
                    disabled={pwLoading}
                    autoComplete="new-password"
                  />
                  <input
                    style={inputStyle}
                    type="password"
                    placeholder="Confirm password"
                    value={confirmPw}
                    onChange={(e) => setConfirmPw(e.target.value)}
                    disabled={pwLoading}
                    autoComplete="new-password"
                  />
                  {pwError && <div style={alertError}><span>{pwError}</span></div>}
                  {pwSuccess && <div style={alertSuccess}><span>Password set</span></div>}
                  {newPw.trim().length > 0 && newPw.trim().length < 10 && (
                    <span style={{ fontSize: 12, color: "var(--ak-color-error, #dc2626)" }}>Password must be at least 10 characters</span>
                  )}
                  {newPw.trim().length >= 10 && confirmPw.trim().length > 0 && newPw !== confirmPw && (
                    <span style={{ fontSize: 12, color: "var(--ak-color-error, #dc2626)" }}>Passwords do not match</span>
                  )}
                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      type="button"
                      style={btnOutlinedStyle}
                      onClick={() => { setSetPwStep("idle"); setSetPwCode(""); setPwError(null); }}
                      disabled={pwLoading}
                    >
                      Back
                    </button>
                    <button
                      type="button"
                      onClick={confirmSetPasswordWithCode}
                      disabled={
                        pwLoading ||
                        setPwCode.trim().length !== 6 ||
                        newPw.trim().length < 10 ||
                        newPw !== confirmPw
                      }
                      style={{ ...btnStyle, flex: 1, opacity: (pwLoading || setPwCode.trim().length !== 6 || newPw.trim().length < 10 || newPw !== confirmPw) ? 0.5 : 1 }}
                    >
                      {pwLoading ? <Spinner size={16} /> : "Set Password"}
                    </button>
                  </div>
                </form>
              )}
            </div>
          )}

          {/* Change Email moved to the Profile tab — see below. */}
        </div>
      )}

      {/* Security Tab */}
      {tab === "security" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 14, fontWeight: 600 }}>Two-Factor Authentication</span>
            <span style={{
              fontSize: 12,
              fontWeight: 600,
              color: totpEnabled ? "var(--ak-color-success, #16a34a)" : "var(--ak-color-text-secondary, #666)",
            }}>
              {totpEnabled ? "Enabled" : "Disabled"}
            </span>
          </div>

          <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0 }}>
            {totpEnabled
              ? "Your account is protected with two-factor authentication."
              : "Add an extra layer of security by enabling two-factor authentication with an authenticator app."}
          </p>

          {/* Idle — show setup or disable button */}
          {totpStep === "idle" && !totpEnabled && (
            <button
              style={btnStyle}
              onClick={() => { setupGate.reset(); setTotpError(null); setTotpStep("confirmSetup"); }}
            >
              Set up 2FA
            </button>
          )}

          {/* Confirm setup — same re-auth gate as disable. A stolen
              access token alone can't initiate enrollment (or the
              attacker could bind their own authenticator and the
              victim would be locked out behind a 2FA they don't
              control). */}
          {totpStep === "confirmSetup" && (
            <form
              style={{ display: "flex", flexDirection: "column", gap: 10 }}
              onSubmit={(e) => e.preventDefault()}
              onKeyDown={(e) => { if (e.key === "Enter") e.preventDefault(); }}
            >
              <input type="text" name="username" autoComplete="username" value={user?.email || ""} readOnly style={{ display: "none" }} tabIndex={-1} />
              <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0, lineHeight: 1.5 }}>
                Verify your identity to enable two-factor authentication.
              </p>

              <ReauthGateFields gate={setupGate} loading={totpLoading} userEmail={user?.email} inputStyle={inputStyle} buttonStyle={btnOutlinedStyle} Spinner={Spinner} />

              {totpError && <div style={alertError}><span>{totpError}</span></div>}
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  type="button"
                  style={btnOutlinedStyle}
                  onClick={() => {
                    setTotpStep("idle");
                    setupGate.reset();
                    setTotpError(null);
                  }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={startTotpSetup}
                  disabled={totpLoading || !setupGate.ready}
                  style={{ ...btnStyle, opacity: (totpLoading || !setupGate.ready) ? 0.5 : 1 }}
                >
                  {totpLoading ? <Spinner size={16} /> : "Continue"}
                </button>
              </div>
            </form>
          )}

          {totpStep === "idle" && totpEnabled && (
            <button
              style={{ ...btnOutlinedStyle, color: "var(--ak-color-error, #dc2626)", borderColor: "var(--ak-color-error, #dc2626)" }}
              onClick={() => setTotpStep("confirmDisable")}
            >
              Disable 2FA
            </button>
          )}

          {/* Confirm disable */}
          {totpStep === "confirmDisable" && (
            <form
              style={{ display: "flex", flexDirection: "column", gap: 10 }}
              onSubmit={(e) => e.preventDefault()}
              onKeyDown={(e) => { if (e.key === "Enter") e.preventDefault(); }}
            >
              <input type="text" name="username" autoComplete="username" value={user?.email || ""} readOnly style={{ display: "none" }} tabIndex={-1} />
              <div style={alertWarning}>
                <span>This will remove two-factor authentication from your account.</span>
              </div>

              <ReauthGateFields gate={disableGate} loading={totpLoading} userEmail={user?.email} inputStyle={inputStyle} buttonStyle={btnOutlinedStyle} Spinner={Spinner} />

              {totpError && <div style={alertError}><span>{totpError}</span></div>}
              <div style={{ display: "flex", gap: 8 }}>
                <button
                  type="button"
                  style={btnOutlinedStyle}
                  onClick={() => {
                    setTotpStep("idle");
                    disableGate.reset();
                    setTotpError(null);
                  }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={disableTotp}
                  disabled={totpLoading || !disableGate.ready}
                  style={{
                    ...btnStyle,
                    background: "var(--ak-color-error, #dc2626)",
                    opacity: (totpLoading || !disableGate.ready) ? 0.5 : 1,
                  }}
                >
                  {totpLoading ? <Spinner size={16} /> : "Disable 2FA"}
                </button>
              </div>
            </form>
          )}

          {/* Scan QR */}
          {totpStep === "scan" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
              <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0 }}>
                Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.):
              </p>
              <div style={{ textAlign: "center", padding: 16 }}>
                {totpUri && <QRCodeImg data={totpUri} size={200} />}
              </div>
              <button style={btnStyle} onClick={() => setTotpStep("verify")}>
                I've scanned it
              </button>
            </div>
          )}

          {/* Verify code */}
          {totpStep === "verify" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0 }}>
                Enter the 6-digit code from your authenticator app:
              </p>
              <input
                style={{ ...inputStyle, textAlign: "center", letterSpacing: 4, fontSize: 18 }}
                type="text"
                placeholder="000000"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                maxLength={6}
                disabled={totpLoading}
              />
              {totpError && <div style={alertError}><span>{totpError}</span></div>}
              <button style={{ ...btnStyle, opacity: (totpLoading || totpCode.trim().length < 6) ? 0.5 : 1 }} onClick={verifyTotp} disabled={totpLoading || totpCode.trim().length < 6}>
                {totpLoading ? <Spinner size={16} /> : "Verify & Enable"}
              </button>
            </div>
          )}

          {/* Backup codes */}
          {totpStep === "backup" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <div style={alertSuccess}><span>Two-factor authentication enabled!</span></div>
              <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0 }}>
                Save these backup codes somewhere safe. You can use them to sign in if you lose your authenticator.
              </p>
              <div style={{
                background: "var(--ak-color-surface, #f5f5f5)",
                borderRadius: 8,
                padding: 16,
                fontFamily: "monospace",
                fontSize: 13,
                lineHeight: 2,
              }}>
                {backupCodes.map((c, i) => <div key={i}>{c}</div>)}
              </div>
              <button style={btnStyle} onClick={() => { setTotpStep("idle"); setTotpCode(""); }}>
                Done
              </button>
            </div>
          )}

          {/* Passkeys */}
          {passkeysAvailable && (
            <div style={{ borderTop: "1px solid var(--ak-color-border, #e5e5e5)", marginTop: 16, paddingTop: 16, display: "flex", flexDirection: "column", gap: 12 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: 14, fontWeight: 600 }}>Passkeys</span>
                <span style={{ fontSize: 12, fontWeight: 600, color: passkeys.length > 0 ? "var(--ak-color-success, #16a34a)" : "var(--ak-color-text-secondary, #666)" }}>
                  {passkeys.length} registered
                </span>
              </div>
              <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0 }}>
                Sign in faster with Face ID, Touch ID, Windows Hello, or a security key. Passkeys never leave your device.
              </p>
              {passkeyError && <div style={alertError}><span>{passkeyError}</span></div>}
              {passkeysLoading ? (
                <div style={{ textAlign: "center", padding: 12 }}><Spinner size={16} /></div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {passkeys.map((p) => (
                    <div key={p.id} style={{
                      display: "flex", flexDirection: "column",
                      padding: "10px 12px",
                      border: "1px solid var(--ak-color-border, #d1d5db)",
                      borderRadius: "var(--ak-radius-md, 8px)",
                      background: "var(--ak-color-card-bg, #fff)",
                      gap: 8,
                    }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                      <div style={{ display: "flex", flexDirection: "column", gap: 2, flex: 1, minWidth: 0 }}>
                        {passkeyRenamingId === p.id ? (
                          <div style={{ display: "flex", gap: 6 }}>
                            <input
                              style={{ ...inputStyle, padding: "6px 10px", fontSize: 13 }}
                              value={passkeyRenameValue}
                              onChange={(e) => setPasskeyRenameValue(e.target.value)}
                              maxLength={80}
                              autoFocus
                              onKeyDown={(e) => { if (e.key === "Enter") void onRenamePasskey(p.id); if (e.key === "Escape") setPasskeyRenamingId(null); }}
                            />
                            <button style={{ ...btnOutlinedStyle, padding: "6px 12px", fontSize: 12 }} onClick={() => void onRenamePasskey(p.id)}>Save</button>
                          </div>
                        ) : (
                          <>
                            <span style={{ fontSize: 13, fontWeight: 600, display: "flex", alignItems: "center", gap: 6 }}>
                              <Icon name="key" size={12} />
                              {p.name || p.authenticatorName || "Unnamed passkey"}
                              {p.backupEligible && <span title="Synced across devices" style={{ fontSize: 10, color: "var(--ak-color-text-secondary, #666)" }}>· synced</span>}
                            </span>
                            <span style={{ fontSize: 11, color: "var(--ak-color-text-secondary, #666)" }}>
                              Added {formatRelative(p.createdAt)}
                              {p.lastUsedAt && ` · Last used ${formatRelative(p.lastUsedAt)}`}
                            </span>
                          </>
                        )}
                      </div>
                      {passkeyRenamingId !== p.id && passkeyConfirmingId !== p.id && (
                        <div style={{ display: "flex", gap: 4 }}>
                          <button
                            style={{ ...btnOutlinedStyle, padding: "6px 10px", fontSize: 12 }}
                            onClick={() => { setPasskeyRenamingId(p.id); setPasskeyRenameValue(p.name || ""); }}
                          >
                            Rename
                          </button>
                          <button
                            style={{ ...btnOutlinedStyle, padding: "6px 10px", fontSize: 12, color: "var(--ak-color-error, #dc2626)", borderColor: "var(--ak-color-error, #dc2626)" }}
                            onClick={() => { passkeyGate.reset(); setPasskeyError(null); setPasskeyConfirmingId(p.id); }}
                            disabled={passkeyDeletingId === p.id}
                          >
                            <Icon name="trash" size={12} />
                          </button>
                        </div>
                      )}
                    </div>
                    {/* Per-row delete-confirmation form. Reuses the
                        shared re-auth gate so users without a password
                        still have a path (email-OTP). */}
                    {passkeyConfirmingId === p.id && (
                      <form
                        style={{ display: "flex", flexDirection: "column", gap: 8, paddingTop: 4, borderTop: "1px dashed var(--ak-color-border, #e5e5e5)", marginTop: 4 }}
                        onSubmit={(e) => e.preventDefault()}
                        onKeyDown={(e) => { if (e.key === "Enter") e.preventDefault(); }}
                      >
                        <input type="text" name="username" autoComplete="username" value={user?.email || ""} readOnly style={{ display: "none" }} tabIndex={-1} />
                        <p style={{ fontSize: 12, color: "var(--ak-color-text-secondary, #666)", margin: 0, lineHeight: 1.5 }}>
                          Verify your identity to delete this passkey.
                        </p>
                        <ReauthGateFields gate={passkeyGate} loading={passkeyDeletingId === p.id} userEmail={user?.email} inputStyle={inputStyle} buttonStyle={btnOutlinedStyle} Spinner={Spinner} />
                        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                          <button
                            type="button"
                            style={{ ...btnOutlinedStyle, padding: "6px 12px", fontSize: 12 }}
                            onClick={() => { setPasskeyConfirmingId(null); passkeyGate.reset(); setPasskeyError(null); }}
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              const body = passkeyGate.body();
                              if (!body) return;
                              void onDeletePasskey(p.id, body);
                            }}
                            disabled={passkeyDeletingId === p.id || !passkeyGate.ready}
                            style={{
                              ...btnStyle,
                              padding: "6px 12px",
                              fontSize: 12,
                              background: "var(--ak-color-error, #dc2626)",
                              opacity: (passkeyDeletingId === p.id || !passkeyGate.ready) ? 0.5 : 1,
                            }}
                          >
                            {passkeyDeletingId === p.id ? <Spinner size={12} /> : "Delete passkey"}
                          </button>
                        </div>
                      </form>
                    )}
                    </div>
                  ))}
                  {passkeys.length === 0 && !passkeysLoading && (
                    <span style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)" }}>No passkeys registered yet</span>
                  )}
                </div>
              )}
              <button
                style={{ ...btnStyle, opacity: passkeyAdding ? 0.5 : 1 }}
                onClick={onAddPasskey}
                disabled={passkeyAdding}
              >
                {passkeyAdding ? <Spinner size={16} /> : <><Icon name="fingerprint" size={14} /> Add a passkey</>}
              </button>
            </div>
          )}

          {/* Delete Account — only when the app's admin allows it. */}
          {allowAccountDeletion && (
            <div style={{ borderTop: "1px solid var(--ak-color-border, #e5e5e5)", marginTop: 16, paddingTop: 16 }}>
              {deleteStep === "idle" && (
                <button
                  style={{ ...btnOutlinedStyle, color: "var(--ak-color-error, #dc2626)", borderColor: "var(--ak-color-error, #dc2626)" }}
                  onClick={() => setDeleteStep("confirm")}
                >
                  Delete Account
                </button>
              )}
              {deleteStep === "confirm" && (
                <form
                  style={{ display: "flex", flexDirection: "column", gap: 10 }}
                  onSubmit={(e) => e.preventDefault()}
                  onKeyDown={(e) => { if (e.key === "Enter") e.preventDefault(); }}
                >
                  <input type="text" name="username" autoComplete="username" value={user?.email || ""} readOnly style={{ display: "none" }} tabIndex={-1} />
                  <div style={alertError}>
                    <span>This will permanently delete your account and all associated data. This cannot be undone.</span>
                  </div>
                  <input
                    style={inputStyle}
                    type="password"
                    placeholder="Enter your password to confirm"
                    value={deletePw}
                    onChange={(e) => setDeletePw(e.target.value)}
                    disabled={deleteLoading}
                    autoComplete="current-password"
                  />
                  {deleteError && <div style={alertError}><span>{deleteError}</span></div>}
                  <div style={{ display: "flex", gap: 8 }}>
                    <button type="button" style={btnOutlinedStyle} onClick={() => { setDeleteStep("idle"); setDeletePw(""); setDeleteError(null); }}>
                      Cancel
                    </button>
                    <button
                      type="button"
                      onClick={deleteAccount}
                      disabled={deleteLoading || !deletePw.trim()}
                      style={{ ...btnStyle, background: "var(--ak-color-error, #dc2626)", opacity: (deleteLoading || !deletePw.trim()) ? 0.5 : 1 }}
                    >
                      {deleteLoading ? <Spinner size={16} /> : "Delete My Account"}
                    </button>
                  </div>
                </form>
              )}
            </div>
          )}
        </div>
      )}

      {/* Fields Tab */}
      {tab === "profile" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {/* Email — read-only display + (when allowed) inline change-email
              flow. Used to live under Password but conceptually it belongs
              with identity, not credentials. */}
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span style={{ fontSize: 12, color: "var(--ak-color-text-secondary, #666)", fontWeight: 600 }}>Email</span>
            <span style={{ fontSize: 14, fontFamily: "monospace" }}>{displayEmail || "—"}</span>
          </div>

          {/* Change Email — gated by the per-app `allowEmailChange` flag
              (admin → General tab). Also requires email/password as the
              primary auth method, since the server-side flow needs
              password confirmation. The OAuth-only path (no password
              ever) gets handled inside via the password-set hint. */}
          {allowEmailChange && showPasswordTab && (
            <div style={{ borderTop: "1px solid var(--ak-color-border, #e5e5e5)", marginTop: 4, paddingTop: 12 }}>
              {emailStep === "idle" && (
                hasPassword ? (
                  <button style={btnOutlinedStyle} onClick={() => { setEmailStep("form"); setEmailError(null); setEmailSuccess(null); }}>
                    Change Email Address
                  </button>
                ) : (
                  <div style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", lineHeight: 1.5 }}>
                    To change your email, first{" "}
                    <button
                      type="button"
                      onClick={() => setTab("password")}
                      style={{
                        background: "none", border: "none", padding: 0,
                        color: "var(--ak-color-primary, #6366f1)",
                        textDecoration: "underline", cursor: "pointer",
                        fontSize: "inherit", fontWeight: 600,
                      }}
                    >
                      set a password
                    </button>
                    {" "}— the change-email flow asks you to confirm it.
                  </div>
                )
              )}

              {emailStep === "form" && (
                <form
                  style={{ display: "flex", flexDirection: "column", gap: 10 }}
                  onSubmit={(e) => e.preventDefault()}
                  onKeyDown={(e) => { if (e.key === "Enter") e.preventDefault(); }}
                >
                  <input type="text" name="username" autoComplete="username" value={user?.email || ""} readOnly style={{ display: "none" }} tabIndex={-1} />
                  <input
                    style={inputStyle}
                    type="password"
                    placeholder="Current password"
                    value={emailPw}
                    onChange={(e) => setEmailPw(e.target.value)}
                    disabled={emailLoading}
                    autoComplete="current-password"
                  />
                  <input
                    style={inputStyle}
                    type="email"
                    placeholder="New email address"
                    value={emailNew}
                    onChange={(e) => setEmailNew(e.target.value)}
                    disabled={emailLoading}
                    autoComplete="email"
                  />
                  {emailError && <div style={alertError}><span>{emailError}</span></div>}
                  <div style={{ display: "flex", gap: 8 }}>
                    <button type="button" style={btnOutlinedStyle} onClick={() => { setEmailStep("idle"); setEmailPw(""); setEmailNew(""); setEmailError(null); }}>Cancel</button>
                    <button
                      type="button"
                      onClick={requestEmailChange}
                      disabled={emailLoading || !emailPw.trim() || !emailNew.trim()}
                      style={{ ...btnStyle, flex: 1, opacity: (emailLoading || !emailPw.trim() || !emailNew.trim()) ? 0.5 : 1 }}
                    >
                      {emailLoading ? <Spinner size={16} /> : "Send Code"}
                    </button>
                  </div>
                </form>
              )}

              {emailStep === "verify" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
                  <p style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)", margin: 0 }}>
                    Verification codes were sent to both your current and new email addresses. Enter both codes below.
                  </p>
                  <input
                    style={{ ...inputStyle, textAlign: "center", letterSpacing: 4, fontSize: 18 }}
                    type="text"
                    placeholder="Code sent to your current email"
                    value={emailOldCode}
                    onChange={(e) => setEmailOldCode(e.target.value)}
                    maxLength={6}
                    disabled={emailLoading}
                  />
                  <input
                    style={{ ...inputStyle, textAlign: "center", letterSpacing: 4, fontSize: 18 }}
                    type="text"
                    placeholder="Code sent to your new email"
                    value={emailNewCode}
                    onChange={(e) => setEmailNewCode(e.target.value)}
                    maxLength={6}
                    disabled={emailLoading}
                  />
                  {emailError && <div style={alertError}><span>{emailError}</span></div>}
                  <div style={{ display: "flex", gap: 8 }}>
                    <button style={btnOutlinedStyle} onClick={() => { setEmailStep("form"); setEmailOldCode(""); setEmailNewCode(""); setEmailError(null); }}>Back</button>
                    <button
                      onClick={verifyEmailChange}
                      disabled={emailLoading || emailOldCode.trim().length < 6 || emailNewCode.trim().length < 6}
                      style={{ ...btnStyle, flex: 1, opacity: (emailLoading || emailOldCode.trim().length < 6 || emailNewCode.trim().length < 6) ? 0.5 : 1 }}
                    >
                      {emailLoading ? <Spinner size={16} /> : "Verify & Change"}
                    </button>
                  </div>
                </div>
              )}

              {emailStep === "done" && emailSuccess && (
                <div style={alertSuccess}><span>{emailSuccess}</span></div>
              )}
            </div>
          )}

          {!fieldsEditing ? (
            <>
              {fields.map((f) => (
                <div key={f.key} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <span style={{ fontSize: 12, color: "var(--ak-color-text-secondary, #666)", fontWeight: 600 }}>{f.label || f.key}</span>
                  <span style={{ fontSize: 14 }}>
                    {f.type === "bool"
                      ? (fieldEdits[f.key] === "true" ? "Yes" : "No")
                      : (fieldEdits[f.key] || "—")}
                  </span>
                </div>
              ))}
              {fieldsSuccess && <span style={{ fontSize: 13, color: "var(--ak-color-success, #16a34a)" }}>✓ Saved</span>}
              {/* Only offer Edit when the app has custom fields configured.
                  Empty Edit → empty form was confusing under the new
                  always-on Profile tab. */}
              {fields.length > 0 && (
                <button
                  style={btnOutlinedStyle}
                  onClick={() => setFieldsEditing(true)}
                >
                  Edit
                </button>
              )}
            </>
          ) : (
            <>
              {fields.map((f) => (
                <div key={f.key} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {f.type === "bool" ? (
                    <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 14, cursor: "pointer" }}>
                      <input
                        type="checkbox"
                        checked={fieldEdits[f.key] === "true"}
                        onChange={(e) => setFieldEdits((prev) => ({ ...prev, [f.key]: e.target.checked ? "true" : "false" }))}
                        disabled={fieldsSaving}
                      />
                      {f.label || f.key}
                    </label>
                  ) : (
                    <>
                      <span style={{ fontSize: 12, color: "var(--ak-color-text-secondary, #666)", fontWeight: 600 }}>{f.label || f.key}</span>
                      <input
                        style={inputStyle}
                        type={f.type === "date" ? "date" : "text"}
                        value={fieldEdits[f.key] ?? ""}
                        onChange={(e) => setFieldEdits((prev) => ({ ...prev, [f.key]: e.target.value }))}
                        disabled={fieldsSaving}
                      />
                    </>
                  )}
                </div>
              ))}
              <div style={{ display: "flex", gap: 8, marginTop: 4 }}>
                <button
                  style={btnOutlinedStyle}
                  onClick={() => setFieldsEditing(false)}
                  disabled={fieldsSaving}
                >
                  Cancel
                </button>
                <button
                  style={{ ...btnStyle, flex: 1, opacity: fieldsSaving ? 0.5 : 1 }}
                  onClick={saveAllFields}
                  disabled={fieldsSaving}
                >
                  {fieldsSaving ? <Spinner size={16} /> : "Save"}
                </button>
              </div>
            </>
          )}

          {/* Log out — sits inside the Profile tab so it's tied to the
              user's identity card rather than competing for attention
              from credential / security flows. Closes the dialog after
              firing logout so the host's auth listeners can take over. */}
          {onLogout && (
            <div style={{ borderTop: "1px solid var(--ak-color-border, #e5e5e5)", marginTop: 16, paddingTop: 16, display: "flex", justifyContent: "center" }}>
              <button
                type="button"
                onClick={async () => {
                  try { await onLogout(); } catch { /* ignore */ }
                  if (onBack) onBack();
                }}
                style={{
                  ...btnOutlinedStyle,
                  color: "var(--ak-color-text)",
                  borderColor: "var(--ak-color-divider)",
                  padding: "8px 24px",
                }}
              >
                <Icon name="logout" size={14} />
                <span style={{ marginLeft: 6 }}>Log out</span>
              </button>
            </div>
          )}
        </div>
      )}

      {tab === "sessions" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {sessionsLoading && <div style={{ textAlign: "center", padding: 20 }}><Spinner size={20} /></div>}
          {sessionsError && <div style={alertError}><span>{sessionsError}</span></div>}
          {!sessionsLoading && sessions.length === 0 && !sessionsError && (
            <span style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)" }}>No active sessions</span>
          )}
          {sessions.length > 1 && (
            <div style={{ marginBottom: 4 }}>
              <button
                type="button"
                onClick={() => {
                  if (confirmingRevokeAll) {
                    void revokeOtherSessions();
                  } else {
                    setConfirmingRevokeAll(true);
                  }
                }}
                disabled={revokingOthers}
                style={{ ...btnOutlinedStyle, width: "auto", padding: "6px 12px", fontSize: 12, color: "var(--ak-color-error, #dc2626)", borderColor: "var(--ak-color-error, #dc2626)" }}
              >
                {revokingOthers ? "Signing out…" : confirmingRevokeAll ? "Click again to confirm" : "Sign out other devices"}
              </button>
            </div>
          )}
          {sessions.map((s) => (
            <div
              key={s.id}
              style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "10px 12px",
                border: s.current ? "2px solid var(--ak-color-primary, #6366f1)" : "1px solid var(--ak-color-border, #d1d5db)",
                borderRadius: "var(--ak-radius-md, 8px)",
                background: "var(--ak-color-card-bg, #fff)",
              }}
            >
              <div style={{ display: "flex", flexDirection: "column", gap: 2, flex: 1, minWidth: 0 }}>
                <span style={{ fontSize: 13, fontWeight: s.current ? 600 : 400 }}>
                  {s.current ? "Current session" : parseBrowser(s.userAgent)}
                </span>
                <span style={{ fontSize: 11, color: "var(--ak-color-text-secondary, #666)" }}>
                  {s.ip && `${s.ip} · `}Last active {formatRelative(s.lastSeenAt)}
                </span>
              </div>
              {!s.current && (
                <button
                  style={{ ...btnOutlinedStyle, width: "auto", padding: "6px 12px", fontSize: 12, color: "var(--ak-color-error, #dc2626)", borderColor: "var(--ak-color-error, #dc2626)" }}
                  onClick={() => revokeSession(s.id)}
                  disabled={revokingId === s.id}
                >
                  {revokingId === s.id ? <Spinner size={12} /> : "Revoke"}
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {tab === "connected" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {identitiesLoading && <div style={{ textAlign: "center", padding: 20 }}><Spinner size={20} /></div>}
          {identitiesError && <div style={alertError}><span>{identitiesError}</span></div>}
          {!identitiesLoading && identities.length === 0 && !identitiesError && (
            <span style={{ fontSize: 13, color: "var(--ak-color-text-secondary, #666)" }}>
              No connected accounts. Sign in with Google, Apple, Microsoft, GitHub, Kakao, or Naver to link one.
            </span>
          )}
          {identities.map((i) => (
            <div
              key={i.provider}
              style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "10px 12px",
                border: "1px solid var(--ak-color-border, #d1d5db)",
                borderRadius: "var(--ak-radius-md, 8px)",
                background: "var(--ak-color-card-bg, #fff)",
              }}
            >
              <div style={{ display: "flex", flexDirection: "column", gap: 2, flex: 1, minWidth: 0 }}>
                <span style={{ fontSize: 13, fontWeight: 600 }}>
                  {PROVIDER_LABEL[i.provider] ?? (i.provider.startsWith("idp:") ? "Single sign-on" : i.provider)}
                </span>
                <span style={{ fontSize: 11, color: "var(--ak-color-text-secondary, #666)" }}>
                  {i.providerEmail ? `${i.providerEmail} · ` : ""}Last sign-in {formatRelative(i.lastLoginAt)}
                </span>
              </div>
              <button
                style={{ ...btnOutlinedStyle, width: "auto", padding: "6px 12px", fontSize: 12, color: "var(--ak-color-error, #dc2626)", borderColor: "var(--ak-color-error, #dc2626)" }}
                onClick={() => disconnectIdentity(i.provider)}
                disabled={disconnectingProvider === i.provider}
              >
                {disconnectingProvider === i.provider ? <Spinner size={12} /> : "Disconnect"}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Branding */}
      {!hideBranding && (
        <p style={{ textAlign: "center", fontSize: 11, color: "var(--ak-color-text-secondary, #666)", opacity: 0.4, marginTop: 32 }}>
          Powered by ManyRows
        </p>
      )}
    </div>
  );
}
