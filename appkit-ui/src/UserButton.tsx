import * as React from "react";
import axios from "axios";
import QRCode from "qrcode";

import Icon from "./Icon";
import Collapse from "./Collapse";
import Spinner from "./Spinner";
import { useAppKitTheme } from "./theme";
import { useManyRowsAppKit, type Account } from "./AppKit";
import { useToast } from "./Toast";
import { useReauthGate, ReauthGateFields } from "./reauthGate";

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
  return (
    <div style={{ textAlign: "center" }}>
      <img src={src} alt="TOTP QR Code" width={size} height={size} />
    </div>
  );
}

function getInitials(name?: string, email?: string): string {
  if (name) {
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) {
      return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    }
    return name.slice(0, 2).toUpperCase();
  }
  if (email) {
    return email.slice(0, 2).toUpperCase();
  }
  return "?";
}

interface UserButtonProps {
  size?: "small" | "medium" | "large";
}

export function UserButton({ size = "medium" }: UserButtonProps) {
  const { appData, logout, refresh, appBaseURL, jwtToken } = useManyRowsAppKit();
  const theme = useAppKitTheme();
  const [open, setOpen] = React.useState(false);
  const [loggingOut, setLoggingOut] = React.useState(false);

  const account = appData?.account;
  const initials = getInitials(account?.name, account?.email);
  const avatarColor = theme.primaryColor;

  const sizeMap = {
    small: 32,
    medium: 40,
    large: 48,
  };

  const handleLogout = async () => {
    setLoggingOut(true);
    try {
      await logout();
    } finally {
      setLoggingOut(false);
      setOpen(false);
    }
  };

  return (
    <>
      <button
        className="ak-icon-btn"
        onClick={() => setOpen(true)}
        style={{ padding: 4 }}
        aria-label="Open profile"
      >
        <span
          className="ak-avatar"
          style={{
            width: sizeMap[size],
            height: sizeMap[size],
            background: avatarColor,
            fontSize: size === "small" ? 14 : size === "large" ? 20 : 16,
          }}
        >
          {initials}
        </span>
      </button>

      <ProfileDialog
        open={open}
        onClose={() => setOpen(false)}
        account={account}
        onLogout={handleLogout}
        loggingOut={loggingOut}
        workspaceBaseURL={appBaseURL}
        jwtToken={jwtToken}
        onNameUpdated={refresh}
      />
    </>
  );
}

interface ProfileDialogProps {
  open: boolean;
  onClose: () => void;
  account?: Account;
  onLogout: () => void;
  loggingOut: boolean;
  workspaceBaseURL: string;
  jwtToken: string | null;
  onNameUpdated: () => void;
}

function ProfileDialog({
  open,
  onClose,
  account,
  onLogout,
  loggingOut,
  workspaceBaseURL,
  jwtToken,
  onNameUpdated,
}: ProfileDialogProps) {
  const { showSuccess } = useToast();
  const theme = useAppKitTheme();
  const dialogRef = React.useRef<HTMLDialogElement>(null);

  const [editing, setEditing] = React.useState(false);
  const [editName, setEditName] = React.useState(account?.name || "");
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const [hasPassword, setHasPassword] = React.useState(false);
  const [passwordSection, setPasswordSection] = React.useState(false);
  const [newPassword, setNewPassword] = React.useState("");
  const [confirmPassword, setConfirmPassword] = React.useState("");
  const [passwordLoading, setPasswordLoading] = React.useState(false);
  const [passwordError, setPasswordError] = React.useState<string | null>(null);
  const [passwordVisible, setPasswordVisible] = React.useState(false);

  const [totpSection, setTotpSection] = React.useState<"closed" | "confirmSetup" | "setup" | "disable" | "backup">("closed");
  const [totpLoading, setTotpLoading] = React.useState(false);
  const [totpError, setTotpError] = React.useState<string | null>(null);
  const [totpEnabled, setTotpEnabled] = React.useState(false);
  const [totpUri, setTotpUri] = React.useState("");
  const [backupCodes, setBackupCodes] = React.useState<string[]>([]);
  const [totpVerifyCode, setTotpVerifyCode] = React.useState("");
  const [totpPassword, setTotpPassword] = React.useState("");
  const [totpSetupStep, setTotpSetupStep] = React.useState<"qr" | "verify">("qr");

  const initials = getInitials(account?.name, account?.email);
  const avatarColor = theme.primaryColor;

  const extractErr = (err: any, fallback: string): string => {
    const data = err?.response?.data;
    if (typeof data === "string" && data.trim()) return data.trim();
    if (data && typeof data === "object") {
      if (typeof data.error === "string" && data.error.trim()) return data.error.trim();
      if (typeof data.message === "string" && data.message.trim()) return data.message.trim();
    }
    return fallback;
  };

  const authHeaders = React.useMemo(
    () => ({
      headers: { Authorization: `Bearer ${jwtToken}` },
      withCredentials: false as const,
      responseType: "json" as const,
    }),
    [jwtToken]
  );

  // Sensitive-op re-auth gates. Backend requires { password } or
  // { code } body on /a/totp/setup, /a/totp/disable. primaryAuthMethod
  // isn't a prop here, so the gate defaults to "password path" via
  // useReauthGate's fallback; users without a password set get the
  // email-OTP flow instead.
  const gateOptions = {
    primaryAuthMethod: undefined,
    hasPassword,
    userEmail: account?.email,
    workspaceBaseUrl: workspaceBaseURL,
    axios,
    axiosConfig: authHeaders,
  };
  const setupGate = useReauthGate({ ...gateOptions, setError: setTotpError });
  const disableGate = useReauthGate({ ...gateOptions, setError: setTotpError });

  // Open/close native dialog
  React.useEffect(() => {
    const el = dialogRef.current;
    if (!el) return;
    if (open && !el.open) {
      el.showModal();
    } else if (!open && el.open) {
      el.close();
    }
  }, [open]);

  // Reset state when opening
  React.useEffect(() => {
    if (open) {
      setEditName(account?.name || "");
      setEditing(false);
      setError(null);
      setPasswordSection(false);
      setNewPassword("");
      setConfirmPassword("");
      setPasswordError(null);
      setPasswordVisible(false);
      setTotpSection("closed");
      setTotpError(null);
      setTotpVerifyCode("");
      setTotpPassword("");
      setTotpSetupStep("qr");

      if (jwtToken) {
        axios
          .get(`${workspaceBaseURL}/a/me`, authHeaders)
          .then((res) => {
            const u = res.data?.user;
            setTotpEnabled(!!u?.totpEnabled);
            setHasPassword(!!u?.passwordSetAt);
          })
          .catch(() => {});
      }
    }
  }, [open, account?.name, jwtToken, workspaceBaseURL, authHeaders]);

  // Close on backdrop click
  const handleDialogClick = (e: React.MouseEvent<HTMLDialogElement>) => {
    if (e.target === dialogRef.current) onClose();
  };

  const handleTotpSetup = async () => {
    const body = setupGate.body();
    if (!body) {
      setTotpError(setupGate.usePasswordPath ? "Password is required to start setup" : "Enter the 6-digit code from your email");
      return;
    }
    setTotpLoading(true);
    setTotpError(null);
    try {
      const res = await axios.post(`${workspaceBaseURL}/a/totp/setup`, body, authHeaders);
      setTotpUri(res.data.uri);
      setTotpSetupStep("qr");
      setTotpSection("setup");
      setupGate.reset();
    } catch (err: any) {
      setTotpError(extractErr(err, "Failed to start TOTP setup"));
    } finally {
      setTotpLoading(false);
    }
  };

  const handleTotpEnable = async () => {
    const trimmed = totpVerifyCode.trim();
    if (!trimmed) return;
    setTotpLoading(true);
    setTotpError(null);
    try {
      const res = await axios.post(`${workspaceBaseURL}/a/totp/enable`, { code: trimmed }, authHeaders);
      setBackupCodes(res.data.backupCodes || []);
      setTotpEnabled(true);
      setTotpSection("backup");
      setTotpVerifyCode("");
      showSuccess("Two-factor authentication enabled");
    } catch (err: any) {
      setTotpError(extractErr(err, "Invalid code"));
    } finally {
      setTotpLoading(false);
    }
  };

  const handleTotpDisable = async () => {
    const body = disableGate.body();
    if (!body) {
      setTotpError(disableGate.usePasswordPath ? "Password is required to disable 2FA" : "Enter the 6-digit code from your email");
      return;
    }
    setTotpLoading(true);
    setTotpError(null);
    try {
      await axios.post(`${workspaceBaseURL}/a/totp/disable`, body, authHeaders);
      setTotpEnabled(false);
      setTotpSection("closed");
      disableGate.reset();
      setTotpPassword("");
      showSuccess("Two-factor authentication disabled");
    } catch (err: any) {
      setTotpError(extractErr(err, "Failed to disable 2FA"));
    } finally {
      setTotpLoading(false);
    }
  };

  const handleRegenerateBackupCodes = async () => {
    if (!totpPassword.trim()) {
      setTotpError("Password is required");
      return;
    }
    setTotpLoading(true);
    setTotpError(null);
    try {
      const res = await axios.post(
        `${workspaceBaseURL}/a/totp/backup-codes`,
        { password: totpPassword },
        authHeaders,
      );
      setBackupCodes(res.data.backupCodes || []);
      setTotpSection("backup");
      setTotpPassword("");
      showSuccess("Backup codes regenerated");
    } catch (err: any) {
      setTotpError(extractErr(err, "Failed to regenerate backup codes"));
    } finally {
      setTotpLoading(false);
    }
  };

  const totpSecret = React.useMemo(() => {
    try {
      const url = new URL(totpUri);
      return url.searchParams.get("secret") || "";
    } catch {
      return "";
    }
  }, [totpUri]);

  const handleSave = async () => {
    const trimmed = editName.trim();
    if (!trimmed) {
      setError("Display name is required");
      return;
    }
    if (trimmed.length > 200) {
      setError("Display name is too long");
      return;
    }
    if (trimmed === account?.name) {
      setEditing(false);
      return;
    }

    setSaving(true);
    setError(null);

    try {
      await axios.post(
        `${workspaceBaseURL}/a/profile/display-name`,
        { displayName: trimmed },
        {
          headers: {
            Authorization: `Bearer ${jwtToken}`,
            "Content-Type": "application/json",
          },
        }
      );
      setEditing(false);
      onNameUpdated();
      showSuccess("Display name updated");
    } catch (err: any) {
      const msg = extractErr(err, "Failed to update name");
      setError(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleSetPassword = async () => {
    const pw = newPassword.trim();
    if (pw.length < 10) {
      setPasswordError("Password must be at least 10 characters");
      return;
    }
    if (pw !== confirmPassword) {
      setPasswordError("Passwords do not match");
      return;
    }
    setPasswordLoading(true);
    setPasswordError(null);
    try {
      await axios.post(`${workspaceBaseURL}/a/set-password`, { password: pw }, authHeaders);
      setHasPassword(true);
      setPasswordSection(false);
      setNewPassword("");
      setConfirmPassword("");
      showSuccess("Password set successfully");
    } catch (err: any) {
      setPasswordError(extractErr(err, "Failed to set password"));
    } finally {
      setPasswordLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleSave();
    } else if (e.key === "Escape") {
      setEditing(false);
      setEditName(account?.name || "");
      setError(null);
    }
  };

  return (
    <dialog
      ref={dialogRef}
      className="ak-dialog"
      onClick={handleDialogClick}
      onClose={onClose}
      aria-labelledby="ak-profile-title"
    >
      <div className="ak-dialog-title">
        <div className="ak-stack-row ak-items-center ak-justify-between">
          <h2 id="ak-profile-title" className="ak-h6" style={{ fontWeight: 600 }}>
            Profile
          </h2>
          <button className="ak-icon-btn ak-icon-btn-sm" onClick={onClose} aria-label="Close">
            <Icon name="close" size={14} />
          </button>
        </div>
      </div>

      <div className="ak-dialog-content">
        <div className="ak-stack ak-gap-6" style={{ paddingTop: 4 }}>
          {/* Avatar and name */}
          <div className="ak-stack-row ak-gap-4 ak-items-center">
            <span
              className="ak-avatar"
              style={{ width: 64, height: 64, background: avatarColor, fontSize: 24 }}
            >
              {initials}
            </span>
            <div className="ak-stack ak-gap-1 ak-min-w-0 ak-flex-1">
              <p className="ak-h6" style={{ fontWeight: 600 }}>{account?.name || "User"}</p>
              <p className="ak-body2 ak-text-secondary ak-truncate">{account?.email}</p>
            </div>
          </div>

          <hr className="ak-divider" />

          {error && (
            <div className="ak-alert ak-alert-error" role="alert">
              <span className="ak-alert-content">{error}</span>
              <button className="ak-alert-close" onClick={() => setError(null)} aria-label="Close">
                <Icon name="close" size={12} />
              </button>
            </div>
          )}

          {/* Account details */}
          <div className="ak-stack ak-gap-4">
            <div>
              <div className="ak-stack-row ak-items-center ak-justify-between" style={{ marginBottom: 4 }}>
                <span className="ak-caption ak-text-secondary ak-font-bold">Display Name</span>
                {!editing && (
                  <button
                    className="ak-icon-btn ak-icon-btn-sm"
                    onClick={() => setEditing(true)}
                    style={{ padding: 2 }}
                    aria-label="Edit display name"
                  >
                    <Icon name="edit" size={12} />
                  </button>
                )}
              </div>
              {editing ? (
                <div className="ak-stack-row ak-gap-2 ak-items-start">
                  <div className="ak-field">
                    <input
                      className={`ak-field-input ak-field-input-sm${error ? " ak-field-input-error" : ""}`}
                      value={editName}
                      onChange={(e) => setEditName(e.target.value)}
                      onKeyDown={handleKeyDown}
                      disabled={saving}
                      autoFocus
                      placeholder="Enter display name"
                    />
                  </div>
                  <button
                    className="ak-icon-btn ak-icon-btn-sm ak-icon-btn-primary"
                    onClick={handleSave}
                    disabled={saving}
                    style={{ marginTop: 4 }}
                    aria-label="Save display name"
                  >
                    {saving ? <Spinner size={18} /> : <Icon name="check" />}
                  </button>
                </div>
              ) : (
                <p className="ak-body1">{account?.name || "—"}</p>
              )}
            </div>
            <div>
              <span className="ak-caption ak-text-secondary ak-font-bold">Email</span>
              <p className="ak-body1">{account?.email || "—"}</p>
            </div>
          </div>

          {/* Set Password */}
          {!hasPassword && (
            <>
              <hr className="ak-divider" />
              <div>
                <div className="ak-stack-row ak-items-center ak-gap-2" style={{ marginBottom: 8 }}>
                  <Icon name="shield" size={14} style={{ color: "var(--ak-color-text-secondary)" }} />
                  <span className="ak-caption ak-text-secondary ak-font-bold">Password</span>
                </div>

                {passwordError && (
                  <div className="ak-alert ak-alert-error" role="alert" style={{ marginBottom: 8 }}>
                    <span className="ak-alert-content">{passwordError}</span>
                    <button className="ak-alert-close" onClick={() => setPasswordError(null)} aria-label="Close">
                      <Icon name="close" size={12} />
                    </button>
                  </div>
                )}

                {!passwordSection ? (
                  <button className="ak-btn ak-btn-outlined ak-btn-sm ak-btn-full" onClick={() => setPasswordSection(true)}>
                    Set a password
                  </button>
                ) : (
                  <div className="ak-stack ak-gap-3">
                    <p className="ak-body2 ak-text-secondary">
                      Set a password so you can sign in with email and password.
                    </p>
                    <div className="ak-field">
                      <input
                        className="ak-field-input ak-field-input-sm"
                        type={passwordVisible ? "text" : "password"}
                        placeholder="New password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        autoComplete="new-password"
                        autoFocus
                      />
                    </div>
                    <div className="ak-field">
                      <input
                        className="ak-field-input ak-field-input-sm"
                        type={passwordVisible ? "text" : "password"}
                        placeholder="Confirm password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        autoComplete="new-password"
                        onKeyDown={(e) => { if (e.key === "Enter") handleSetPassword(); }}
                      />
                    </div>
                    <div className="ak-stack-row ak-gap-2">
                      <button
                        className="ak-btn ak-btn-text ak-btn-sm ak-btn-full"
                        onClick={() => { setPasswordSection(false); setPasswordError(null); setNewPassword(""); setConfirmPassword(""); }}
                      >
                        Cancel
                      </button>
                      <button
                        className="ak-btn ak-btn-contained ak-btn-sm ak-btn-full"
                        onClick={handleSetPassword}
                        disabled={passwordLoading || !newPassword.trim()}
                      >
                        {passwordLoading && <Spinner size={14} white />}
                        {passwordLoading ? "Setting…" : "Set password"}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}

          <hr className="ak-divider" />

          {/* TOTP Management */}
          <div>
            <div className="ak-stack-row ak-items-center ak-justify-between" style={{ marginBottom: 8 }}>
              <div className="ak-stack-row ak-items-center ak-gap-2">
                <Icon name="shield" size={14} style={{ color: "var(--ak-color-text-secondary)" }} />
                <span className="ak-caption ak-text-secondary ak-font-bold">
                  Two-Factor Authentication
                </span>
              </div>
              <span className={`ak-chip ${totpEnabled ? "ak-chip-success" : "ak-chip-default"}`}>
                {totpEnabled ? "Enabled" : "Disabled"}
              </span>
            </div>

            {totpError && (
              <div className="ak-alert ak-alert-error" role="alert" style={{ marginBottom: 8 }}>
                <span className="ak-alert-content">{totpError}</span>
                <button className="ak-alert-close" onClick={() => setTotpError(null)} aria-label="Close">
                  <Icon name="close" size={12} />
                </button>
              </div>
            )}

            {totpSection === "closed" && (
              <div className="ak-stack ak-gap-2">
                {!totpEnabled ? (
                  <button
                    className="ak-btn ak-btn-outlined ak-btn-sm ak-btn-full"
                    onClick={() => { setupGate.reset(); setTotpError(null); setTotpSection("confirmSetup"); }}
                    disabled={totpLoading}
                  >
                    Enable 2FA
                  </button>
                ) : (
                  <div className="ak-stack-row ak-gap-2">
                    <button
                      className="ak-btn ak-btn-outlined ak-btn-sm ak-btn-full"
                      onClick={() => { setTotpSection("backup"); setTotpError(null); setTotpPassword(""); }}
                    >
                      Backup codes
                    </button>
                    <button
                      className="ak-btn ak-btn-outlined ak-btn-sm ak-btn-full ak-btn-error"
                      onClick={() => { setTotpSection("disable"); setTotpError(null); setTotpPassword(""); }}
                    >
                      Disable
                    </button>
                  </div>
                )}
              </div>
            )}

            <Collapse show={totpSection === "setup"}>
              <div className="ak-stack ak-gap-4" style={{ marginTop: 8 }}>
                {totpSetupStep === "qr" && (
                  <>
                    <p className="ak-body2 ak-text-secondary">
                      Scan this QR code with your authenticator app.
                    </p>
                    {totpUri && <QRCodeImg data={totpUri} size={180} />}
                    {totpSecret && (
                      <div className="ak-code-block" style={{ textAlign: "center" }}>
                        {totpSecret}
                      </div>
                    )}
                    <button className="ak-btn ak-btn-contained ak-btn-sm ak-btn-full" onClick={() => setTotpSetupStep("verify")}>
                      Next
                    </button>
                  </>
                )}
                {totpSetupStep === "verify" && (
                  <>
                    <p className="ak-body2 ak-text-secondary">
                      Enter the 6-digit code from your authenticator app.
                    </p>
                    <div className="ak-field">
                      <input
                        className="ak-field-input ak-field-input-sm"
                        value={totpVerifyCode}
                        onChange={(e) => setTotpVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                        onKeyDown={(e) => { if (e.key === "Enter") handleTotpEnable(); }}
                        placeholder="000000"
                        autoFocus
                        maxLength={6}
                        inputMode="numeric"
                        style={{ letterSpacing: "0.5em", textAlign: "center" }}
                      />
                    </div>
                    <button
                      className="ak-btn ak-btn-contained ak-btn-sm ak-btn-full"
                      onClick={handleTotpEnable}
                      disabled={totpLoading || totpVerifyCode.trim().length < 6}
                    >
                      {totpLoading && <Spinner size={14} white />}
                      {totpLoading ? "Verifying…" : "Verify and enable"}
                    </button>
                    <button className="ak-btn ak-btn-text ak-btn-sm" onClick={() => setTotpSetupStep("qr")}>
                      Back
                    </button>
                  </>
                )}
                <button className="ak-btn ak-btn-text ak-btn-sm" onClick={() => setTotpSection("closed")}>
                  Cancel
                </button>
              </div>
            </Collapse>

            <Collapse show={totpSection === "confirmSetup"}>
              <div className="ak-stack ak-gap-4" style={{ marginTop: 8 }}>
                <p className="ak-body2 ak-text-secondary">
                  Verify your identity to enable two-factor authentication.
                </p>
                <div className="ak-field">
                  <ReauthGateFields
                    gate={setupGate}
                    loading={totpLoading}
                    userEmail={account?.email}
                    inputClassName="ak-field-input ak-field-input-sm"
                    buttonClassName="ak-btn ak-btn-outlined ak-btn-sm ak-btn-full"
                    Spinner={Spinner}
                  />
                </div>
                {totpError && <p className="ak-body2" style={{ color: "var(--ak-color-error, #dc2626)" }}>{totpError}</p>}
                <div className="ak-stack-row ak-gap-2">
                  <button className="ak-btn ak-btn-text ak-btn-sm ak-btn-full" onClick={() => { setTotpSection("closed"); setupGate.reset(); setTotpError(null); }}>
                    Cancel
                  </button>
                  <button
                    className="ak-btn ak-btn-contained ak-btn-sm ak-btn-full"
                    onClick={handleTotpSetup}
                    disabled={totpLoading || !setupGate.ready}
                  >
                    {totpLoading && <Spinner size={14} white />}
                    {totpLoading ? "Starting…" : "Continue"}
                  </button>
                </div>
              </div>
            </Collapse>

            <Collapse show={totpSection === "disable"}>
              <div className="ak-stack ak-gap-4" style={{ marginTop: 8 }}>
                <p className="ak-body2 ak-text-secondary">
                  Verify your identity to disable two-factor authentication.
                </p>
                <div className="ak-field">
                  <ReauthGateFields
                    gate={disableGate}
                    loading={totpLoading}
                    userEmail={account?.email}
                    inputClassName="ak-field-input ak-field-input-sm"
                    buttonClassName="ak-btn ak-btn-outlined ak-btn-sm ak-btn-full"
                    Spinner={Spinner}
                  />
                </div>
                {totpError && <p className="ak-body2" style={{ color: "var(--ak-color-error, #dc2626)" }}>{totpError}</p>}
                <div className="ak-stack-row ak-gap-2">
                  <button className="ak-btn ak-btn-text ak-btn-sm ak-btn-full" onClick={() => { setTotpSection("closed"); disableGate.reset(); setTotpError(null); }}>
                    Cancel
                  </button>
                  <button
                    className="ak-btn ak-btn-contained ak-btn-sm ak-btn-full ak-btn-error"
                    onClick={handleTotpDisable}
                    disabled={totpLoading || !disableGate.ready}
                  >
                    {totpLoading && <Spinner size={14} white />}
                    {totpLoading ? "Disabling…" : "Disable 2FA"}
                  </button>
                </div>
              </div>
            </Collapse>

            <Collapse show={totpSection === "backup"}>
              <div className="ak-stack ak-gap-4" style={{ marginTop: 8 }}>
                {backupCodes.length > 0 ? (
                  <>
                    <p className="ak-body2 ak-text-secondary">
                      Save these backup codes. Each can only be used once.
                    </p>
                    <div className="ak-code-block" style={{ fontSize: 13 }}>
                      {backupCodes.map((code) => (
                        <div key={code}>{code}</div>
                      ))}
                    </div>
                    <button className="ak-btn ak-btn-text ak-btn-sm" onClick={() => { setTotpSection("closed"); setBackupCodes([]); }}>
                      Done
                    </button>
                  </>
                ) : (
                  <>
                    <p className="ak-body2 ak-text-secondary">
                      Enter your password to regenerate backup codes. This will invalidate any previous codes.
                    </p>
                    <div className="ak-field">
                      <input
                        className="ak-field-input ak-field-input-sm"
                        type="password"
                        placeholder="Password"
                        value={totpPassword}
                        onChange={(e) => setTotpPassword(e.target.value)}
                        onKeyDown={(e) => { if (e.key === "Enter") handleRegenerateBackupCodes(); }}
                        autoComplete="current-password"
                        autoFocus
                      />
                    </div>
                    <div className="ak-stack-row ak-gap-2">
                      <button className="ak-btn ak-btn-text ak-btn-sm ak-btn-full" onClick={() => setTotpSection("closed")}>
                        Cancel
                      </button>
                      <button
                        className="ak-btn ak-btn-contained ak-btn-sm ak-btn-full"
                        onClick={handleRegenerateBackupCodes}
                        disabled={totpLoading || !totpPassword.trim()}
                      >
                        {totpLoading && <Spinner size={14} white />}
                        {totpLoading ? "Generating…" : "Regenerate codes"}
                      </button>
                    </div>
                  </>
                )}
              </div>
            </Collapse>
          </div>

          <hr className="ak-divider" />

          {/* Actions */}
          <button
            className="ak-btn ak-btn-outlined ak-btn-full ak-btn-error"
            onClick={onLogout}
            disabled={loggingOut}
          >
            {loggingOut ? <Spinner size={16} /> : <Icon name="logout" />}
            {loggingOut ? "Logging out…" : "Log out"}
          </button>
        </div>
      </div>
    </dialog>
  );
}
