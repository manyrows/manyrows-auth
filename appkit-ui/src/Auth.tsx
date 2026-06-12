import * as React from "react";
import axios from "axios";
import QRCode from "qrcode";

import Icon from "./Icon";
import Collapse from "./Collapse";
import Spinner from "./Spinner";
import { withDPoPHeader } from "./dpop";
import {
  decodeRequestOptions,
  encodeAssertionResponse,
  isPasskeySupported,
} from "./webauthnUtil";

const LAST_EMAIL_KEY = "manyrows:lastEmail";

// Defence-in-depth: never navigate an OAuth popup to anything that isn't an
// https:// URL. The authorize URL comes from the manyrows API over HTTPS, but
// if a malformed value ever reached the client it could be `javascript:` or
// `data:` and execute attacker JS in the popup → opener postMessage bridge.
function safePopupUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("Invalid authorize URL");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("Authorize URL must be https");
  }
  return parsed.toString();
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 48 48">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/>
      <path fill="#FBBC05" d="M10.53 28.59a14.5 14.5 0 0 1 0-9.18l-7.98-6.19a24.01 24.01 0 0 0 0 21.56l7.98-6.19z"/>
      <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
    </svg>
  );
}

function AppleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M16.365 1.43c0 1.14-.493 2.27-1.177 3.08-.736.876-1.949 1.547-2.97 1.464-.123-1.09.4-2.232 1.083-2.99.735-.815 2.039-1.467 3.064-1.554zM21.5 17.13c-.563 1.243-.832 1.797-1.557 2.897-1.012 1.535-2.44 3.448-4.21 3.466-1.575.016-1.98-.992-4.118-.984-2.137.013-2.586 1.001-4.16.985-1.77-.018-3.122-1.749-4.135-3.284C0.49 15.94-.16 11.097 1.564 8.05 2.792 5.91 4.733 4.66 6.555 4.66c1.852 0 3.017 1.018 4.555 1.018 1.494 0 2.402-1.018 4.561-1.018 1.622 0 3.342.882 4.567 2.41-4.013 2.197-3.358 7.918 1.262 10.06z"/>
    </svg>
  );
}

function MicrosoftIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 23 23" aria-hidden="true">
      <path fill="#f3f3f3" d="M0 0h23v23H0z"/>
      <path fill="#f35325" d="M1 1h10v10H1z"/>
      <path fill="#81bc06" d="M12 1h10v10H12z"/>
      <path fill="#05a6f0" d="M1 12h10v10H1z"/>
      <path fill="#ffba08" d="M12 12h10v10H12z"/>
    </svg>
  );
}

function GithubIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/>
    </svg>
  );
}

function KakaoIcon() {
  // Kakao speech-bubble symbol, rendered black on the brand-yellow button.
  return (
    <svg width="18" height="18" viewBox="0 0 256 256" aria-hidden="true">
      <path fill="#000000" d="M128 36C70.562 36 24 72.713 24 118c0 29.279 19.466 54.97 48.748 69.477-1.593 5.494-10.237 35.34-10.581 37.69 0 0-.207 1.762.934 2.434s2.483.15 2.483.15c3.286-.46 37.977-24.823 43.96-29.048 6.062.84 12.276 1.297 18.456 1.297 57.438 0 104-36.713 104-82 0-45.287-46.562-82-104-82z"/>
    </svg>
  );
}

function NaverIcon() {
  // Naver "N" mark, rendered white on the brand-green button.
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="#FFFFFF" aria-hidden="true">
      <path d="M16.273 12.845 7.376 0H0v24h7.726V11.155L16.624 24H24V0h-7.727z"/>
    </svg>
  );
}

export interface AuthLabels {
  // Headings
  signInTitle: string;
  setPasswordTitle: string;
  setYourPasswordTitle: string;
  checkYourEmailTitle: string;
  createAccountTitle: string;
  verifyYourEmailTitle: string;
  setAPasswordTitle: string;
  twoFactorTitle: string;

  // Pre-session TOTP enrollment ("Require2FA on user without TOTP")
  totpSetupTitle?: string;
  totpSetupDesc?: string;
  totpSetupManualKey?: string;
  totpSetupVerify?: string;
  totpSetupBackupCodesIntro?: string;
  totpSetupBackupCodesAck?: string;

  // Descriptions
  enterEmailAndPassword: string;
  enterEmailForCode: string;
  enterEmailForPasswordCode: string;
  weSentCodeTo: string; // use {email} placeholder
  enterEmailToGetStarted: string;
  setPasswordOptional: string;
  enterTotpCode: string;
  enterBackupCode: string;

  // Labels
  emailLabel: string;
  emailPlaceholder: string;
  passwordLabel: string;
  passwordPlaceholder: string;
  newPasswordLabel: string;
  newPasswordPlaceholder: string;
  confirmPasswordLabel: string;
  confirmPasswordPlaceholder: string;
  codeLabel: string;
  codePlaceholder: string;
  backupCodeLabel: string;
  backupCodePlaceholder: string;

  // Buttons
  signInWithGoogle: string;
  signingInWithGoogle: string;
  signInWithApple: string;
  signingInWithApple: string;
  signInWithMicrosoft: string;
  signingInWithMicrosoft: string;
  signInWithGithub: string;
  signingInWithGithub: string;
  signInWithKakao: string;
  signingInWithKakao: string;
  signInWithNaver: string;
  signingInWithNaver: string;
  signInWithPasskey: string;
  signingInWithPasskey: string;
  passkeyCancelled: string;
  passkeyNotAvailable: string;
  signIn: string;
  signingIn: string;
  forgotPassword: string;
  createAccount: string;
  continueButton: string;
  sending: string;
  sendCode: string;
  setPassword: string;
  settingPassword: string;
  verify: string;
  verifying: string;
  creatingAccount: string;
  backToSignIn: string;
  changeEmail: string;
  back: string;
  skipForNow: string;
  useAuthenticatorCode: string;
  useBackupCode: string;
  keepMeSignedIn: string;
  alreadyHaveAccount: string;
  logOutAllSessions: string;

  // Success / Error
  checkEmailForCode: string;
  checkEmailForLink: string;
  checkEmailForPasswordResetCode: string;
  magicLinkErrors?: { [code: string]: string };
  useDifferentEmail?: string;
  passwordSetSuccess: string;
  tooManyRequests: string; // use {minutes} placeholder
  tooManyRequestsGeneric: string;
  invalidCredentials: string;
  accessDenied: string;
  accessDeniedNeedAccount: string;
  identityConflict: string;
  requestFailed: string;
  requestFailedWithStatus: string; // use {status} placeholder

  // Password strength
  strengthTooShort: string;
  strengthWeak: string;
  strengthFair: string;
  strengthGood: string;
  strengthStrong: string;

  // Misc
  orDivider: string;
  oauthOnlyPrompt: string;
  oauthOnlyRegisterHint: string;
  magicLinkRegisterHint: string;
  newHerePrompt: string;
  enterCodeFromEmail: string;
  codeMustBe6Digits: string;
  passwordsDoNotMatch: string;
}

const DEFAULT_LABELS: AuthLabels = {
  signInTitle: "Sign in",
  setPasswordTitle: "Set password",
  setYourPasswordTitle: "Set your password",
  checkYourEmailTitle: "Check your email",
  createAccountTitle: "Create account",
  verifyYourEmailTitle: "Verify your email",
  setAPasswordTitle: "Set a password",
  twoFactorTitle: "Two-factor authentication",

  totpSetupTitle: "Set up two-factor authentication",
  totpSetupDesc: "This app requires two-factor authentication. Scan the QR with your authenticator app, then enter the 6-digit code to finish signing in.",
  totpSetupManualKey: "Manual entry key",
  totpSetupVerify: "Verify and finish sign-in",
  totpSetupBackupCodesIntro: "Save these backup codes somewhere safe. Each code works once if you ever lose your authenticator.",
  totpSetupBackupCodesAck: "I've saved my codes — continue",

  enterEmailAndPassword: "Enter your email and password.",
  enterEmailForCode: "Enter your email to receive a sign-in code.",
  enterEmailForPasswordCode: "Enter your email to receive a code for setting your password.",
  weSentCodeTo: "We sent a 6-digit code to {email}.",
  enterEmailToGetStarted: "Enter your email to get started.",
  setPasswordOptional: "Add a password so you can also sign in with email and password. You can skip this for now.",
  enterTotpCode: "Enter the 6-digit code from your authenticator app.",
  enterBackupCode: "Enter one of your backup codes.",

  emailLabel: "Email",
  emailPlaceholder: "you@company.com",
  passwordLabel: "Password",
  passwordPlaceholder: "Enter your password",
  newPasswordLabel: "New password",
  newPasswordPlaceholder: "At least 10 characters",
  confirmPasswordLabel: "Confirm password",
  confirmPasswordPlaceholder: "Re-enter your password",
  codeLabel: "6-digit code",
  codePlaceholder: "123456",
  backupCodeLabel: "Backup code",
  backupCodePlaceholder: "Enter backup code",

  signInWithGoogle: "Sign in with Google",
  signInWithApple: "Sign in with Apple",
  signingInWithApple: "Signing in...",
  signInWithMicrosoft: "Sign in with Microsoft",
  signingInWithMicrosoft: "Signing in...",
  signInWithGithub: "Sign in with GitHub",
  signingInWithGithub: "Signing in...",
  signInWithKakao: "Sign in with Kakao",
  signingInWithKakao: "Signing in...",
  signInWithNaver: "Sign in with Naver",
  signingInWithNaver: "Signing in...",
  signInWithPasskey: "Sign in with passkey",
  signingInWithPasskey: "Signing in…",
  passkeyCancelled: "Passkey sign-in cancelled",
  passkeyNotAvailable: "No passkey found for this site. Sign in with your password, then add one from your account settings.",
  signingInWithGoogle: "Signing in...",
  signIn: "Sign in",
  signingIn: "Signing in…",
  forgotPassword: "Forgot password?",
  createAccount: "Create account",
  continueButton: "Continue",
  sending: "Sending…",
  sendCode: "Send code",
  setPassword: "Set password",
  settingPassword: "Setting password…",
  verify: "Verify",
  verifying: "Verifying…",
  creatingAccount: "Creating account…",
  backToSignIn: "Back to sign in",
  changeEmail: "Change email",
  back: "Back",
  skipForNow: "Skip for now",
  useAuthenticatorCode: "Use authenticator code",
  useBackupCode: "Use a backup code",
  keepMeSignedIn: "Keep me signed in",
  alreadyHaveAccount: "Already have an account? Sign in",
  logOutAllSessions: "Log out of all other sessions",

  checkEmailForCode: "Check your email for a 6-digit code.",
  checkEmailForLink: "Check your email for a sign-in link. The link expires in 15 minutes.",
  checkEmailForPasswordResetCode: "Check your email for a 6-digit code to set your password.",
  magicLinkErrors: {
    invalid_token: "This sign-in link is invalid or has already been used.",
    registration_disabled: "This app doesn't allow new sign-ups. Ask an admin to invite you.",
    domain_not_allowed: "Your email domain isn't allowed to sign in to this app.",
    limit_reached: "This workspace has reached its user limit. Contact the workspace owner.",
    account_banned: "This account is no longer allowed to sign in.",
    account_disabled: "This account is disabled.",
    totp_required: "Two-factor authentication is required for this account. Magic-link sign-in isn't supported when 2FA is on.",
    totp_setup_required: "This app requires two-factor authentication. Set it up by signing in with email + code first, then come back to magic-link sign-in.",
    server_error: "Something went wrong on our end. Please try again.",
    generic: "We couldn't complete the sign-in. Please request a new link.",
  },
  useDifferentEmail: "Use a different email",
  passwordSetSuccess: "Password set successfully! You can now sign in.",
  tooManyRequests: "Too many requests. Please try again in {minutes} minute{s}.",
  tooManyRequestsGeneric: "Too many requests. Please wait a bit and try again.",
  invalidCredentials: "Invalid email or password.",
  accessDenied: "Access denied.",
  accessDeniedNeedAccount: "Access denied. You may need to create an account first.",
  identityConflict: "This email is already linked to a different social account. Sign in with that account, or remove it from your profile first.",
  requestFailed: "Request failed.",
  requestFailedWithStatus: "Request failed ({status}).",

  strengthTooShort: "Too short",
  strengthWeak: "Weak",
  strengthFair: "Fair",
  strengthGood: "Good",
  strengthStrong: "Strong",

  orDivider: "Or sign in with",
  oauthOnlyPrompt: "Choose how you'd like to continue.",
  oauthOnlyRegisterHint: "Don't have an account? It'll be created on your first sign-in.",
  magicLinkRegisterHint: "Don't have an account? It'll be created on your first sign-in.",
  newHerePrompt: "New here?",
  enterCodeFromEmail: "Enter the code from the email.",
  codeMustBe6Digits: "Code must be 6 digits.",
  passwordsDoNotMatch: "Passwords do not match",
};

export interface TokenPairResponse {
  accessToken: string;
  refreshToken: string;
  expiresAt: string;
  expiresIn: number;
  totpSetupRequired?: boolean;
}

type AuthView = "email" | "code" | "password" | "setPassword" | "setPasswordCode" | "register" | "registerCode" | "registerSetPassword" | "totp" | "totpSetup" | "magicLinkSent";

// PrimaryAuthMethod selects the email-form mode shown on the sign-in
// screen. password, code, and magicLink are mutually exclusive (we can
// only show one email form); "none" hides the email form entirely
// (OAuth-only).
type PrimaryAuthMethod = "password" | "code" | "magicLink" | "none";

// SetupQR renders an otpauth:// URL as a QR-code <img>. Small inline
// component so the Auth bundle keeps its own dependency on `qrcode`
// scoped — same pattern as AppKit.tsx and Profile.tsx.
function SetupQR({ uri }: { uri: string }) {
  const [src, setSrc] = React.useState("");
  React.useEffect(() => {
    let cancelled = false;
    QRCode.toDataURL(uri, { width: 200, margin: 4 }).then(
      (dataURL) => { if (!cancelled) setSrc(dataURL); },
      () => { /* ignore — manual entry key still works */ },
    );
    return () => { cancelled = true; };
  }, [uri]);
  if (!src) return <div style={{ width: 200, height: 200 }} />;
  return <img src={src} alt="2FA setup QR" width={200} height={200} />;
}

export default function Auth(props: {
  workspaceBaseUrl: string;
  /**
   * Cookie mode: ManyRows sets HttpOnly mr_at / mr_rt session
   * cookies directly (first-party / same-host or custom-domain
   * CNAME). DPoP proof signing is skipped because there's no
   * JS-readable token to bind.
   */
  cookieMode?: boolean;
  onTokenPair: (tokens: TokenPairResponse, keepSignedIn: boolean) => void;
  primaryAuthMethod?: PrimaryAuthMethod;
  allowRegistration?: boolean;
  appId?: string;
  googleOAuthClientId?: string;
  appleEnabled?: boolean;
  microsoftEnabled?: boolean;
  githubEnabled?: boolean;
  kakaoEnabled?: boolean;
  naverEnabled?: boolean;
  externalIdps?: { slug: string; displayName: string; buttonIcon?: string }[];
  passkeyEnabled?: boolean;
  qrSignInEnabled?: boolean;
  require2fa?: boolean;
  hideBranding?: boolean;
  header?: React.ReactNode;
  labels?: Partial<AuthLabels>;
  initialScreen?: "login" | "register" | "forgot-password";
  // Prefill for the email field (e.g. an OIDC login_hint). Initial
  // value only — the user can edit it freely.
  loginHint?: string;
  onScreenChange?: (screen: "login" | "register" | "forgot-password") => void;
  embedded?: boolean;
  requireConsent?: boolean;
  termsUrl?: string;
  privacyUrl?: string;
  consentVersion?: string;
}) {
  const L = React.useMemo(() => ({ ...DEFAULT_LABELS, ...props.labels }), [props.labels]);
  const baseUrl = props.workspaceBaseUrl;
  const cookieMode = !!props.cookieMode;
  const primaryAuthMethod: PrimaryAuthMethod = props.primaryAuthMethod ?? "password";
  const showPassword = primaryAuthMethod === "password";
  const useOtp = primaryAuthMethod === "code";
  const useMagicLink = primaryAuthMethod === "magicLink";
  const oauthOnly = primaryAuthMethod === "none";
  const allowRegistration = props.allowRegistration === true && !!props.appId;
  const showGoogle = !!props.googleOAuthClientId;
  const showApple = props.appleEnabled === true;
  const showMicrosoft = props.microsoftEnabled === true;
  const showGithub = props.githubEnabled === true;
  const showKakao = props.kakaoEnabled === true;
  const showNaver = props.naverEnabled === true;
  const showQRSignIn = props.qrSignInEnabled === true;

  // Legacy flag kept for the few places that branched on "Google is the
  // only thing we can show". Now equivalent to oauthOnly with Google
  // configured and no other social/passkey options.
  const googleOnly = oauthOnly && showGoogle && !showApple && !showMicrosoft && !showGithub && !showKakao && !showNaver && !props.passkeyEnabled;
  const defaultView: AuthView = (useOtp || useMagicLink) ? "email" : "password";
  // Only honor initialScreen="forgot-password" when this app actually
  // has a password form to recover. In OAuth-only mode (no email field
  // anywhere) /forgot-password would render an empty card with a
  // "Send code" button and nothing to type into. Fall through to the
  // default view (which surfaces the OAuth buttons) so the route is
  // still reachable but lands somewhere coherent.
  const initialView: AuthView = props.initialScreen === "register" && allowRegistration ? "register"
    : (props.initialScreen === "forgot-password" && showPassword) ? "setPassword"
    : defaultView;
  const [view, setView] = React.useState<AuthView>(initialView);
  const [googleLoading, setGoogleLoading] = React.useState(false);
  const [appleLoading, setAppleLoading] = React.useState(false);
  const [microsoftLoading, setMicrosoftLoading] = React.useState(false);
  const [githubLoading, setGithubLoading] = React.useState(false);
  const [kakaoLoading, setKakaoLoading] = React.useState(false);
  const [naverLoading, setNaverLoading] = React.useState(false);
  const [loading, setLoading] = React.useState(false);
  // loginHint only seeds the initial value (useState initializer runs
  // once) — the user can clear or replace it.
  const [email, setEmail] = React.useState(props.loginHint ?? "");
  const [code, setCode] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [confirmPassword, setConfirmPassword] = React.useState("");
  const [logoutAll, setLogoutAll] = React.useState(true);
  const [passwordVisible, setPasswordVisible] = React.useState(false);
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
  const [successMsg, setSuccessMsg] = React.useState<string | null>(null);
  const [totpChallengeToken, setTotpChallengeToken] = React.useState("");
  const [totpCode, setTotpCode] = React.useState("");
  const [useBackupCode, setUseBackupCode] = React.useState(false);
  const [pendingTokens, setPendingTokens] = React.useState<TokenPairResponse | null>(null);
  const [keepSignedIn, setKeepSignedIn] = React.useState(true);
  const [consentChecked, setConsentChecked] = React.useState(false);
  // OAuth signup consent gate — only the register view requires it. Existing
  // users signing in via OAuth from the sign-in view don't need consent, so
  // their provider buttons must NOT be gated (or they'd be dead-ended).
  const oauthConsentBlocked = props.requireConsent === true && view === "register" && !consentChecked;

  // Pre-session TOTP enrollment state. Populated when an upstream
  // sign-in (OTP/password/OAuth/magic-link) hands back a setup
  // challenge instead of a session — the user must enroll TOTP and
  // verify their first code before any session is minted.
  const [totpSetupChallengeToken, setTotpSetupChallengeToken] = React.useState("");
  const [totpSetupSecret, setTotpSetupSecret] = React.useState("");
  const [totpSetupURI, setTotpSetupURI] = React.useState("");
  const [totpSetupCode, setTotpSetupCode] = React.useState("");
  const [totpSetupBackupCodes, setTotpSetupBackupCodes] = React.useState<string[] | null>(null);

  const emailInputRef = React.useRef<HTMLInputElement>(null);
  const codeInputRef = React.useRef<HTMLInputElement>(null);
  const passwordInputRef = React.useRef<HTMLInputElement>(null);
  const totpInputRef = React.useRef<HTMLInputElement>(null);

  React.useEffect(() => {
    try {
      const saved = localStorage.getItem(LAST_EMAIL_KEY);
      if (saved) setEmail(saved);
    } catch {
      // ignore
    }
  }, []);

  // Magic-link consume bootstrap: when ManyRows redirects back to the
  // app URL after consuming a magic-link token, it appends one of:
  //   #mr_session=…&mr_refresh=…&mr_expires=…   (success)
  //   #mr_totp_challenge=…                       (TOTP needed before login)
  //   #mr_magic_error=<code>                     (failure)
  // Read once, hand off, and clear the fragment so refreshes don't
  // replay it.
  React.useEffect(() => {
    if (typeof window === "undefined") return;
    const hash = window.location.hash || "";
    if (!hash.startsWith("#")) return;
    const params = new URLSearchParams(hash.slice(1));
    const errCode = params.get("mr_magic_error");
    const totpChallenge = params.get("mr_totp_challenge");
    const totpSetupChallenge = params.get("mr_totp_setup_challenge");
    const accessToken = params.get("mr_session");
    const refreshToken = params.get("mr_refresh");
    const expiresUnix = params.get("mr_expires");
    const consumed = errCode || totpChallenge || totpSetupChallenge || (accessToken && refreshToken && expiresUnix);
    if (!consumed) return;
    try {
      const url = new URL(window.location.href);
      url.hash = "";
      window.history.replaceState(null, "", url.toString());
    } catch {
      // ignore
    }
    if (errCode) {
      setErrorMsg(L.magicLinkErrors?.[errCode] ?? L.magicLinkErrors?.generic ?? L.requestFailed);
      return;
    }
    if (totpSetupChallenge) {
      void enterTOTPSetup(totpSetupChallenge);
      return;
    }
    if (totpChallenge) {
      setTotpChallengeToken(totpChallenge);
      setTotpCode("");
      setUseBackupCode(false);
      setView("totp");
      return;
    }
    if (accessToken && refreshToken && expiresUnix) {
      const expiresAt = new Date(parseInt(expiresUnix, 10) * 1000).toISOString();
      const expiresIn = Math.max(0, Math.floor((parseInt(expiresUnix, 10) * 1000 - Date.now()) / 1000));
      props.onTokenPair({ accessToken, refreshToken, expiresAt, expiresIn }, true);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  React.useEffect(() => {
    if (view === "email") {
      window.setTimeout(() => emailInputRef.current?.focus(), 50);
    } else if (view === "code" || view === "setPasswordCode") {
      window.setTimeout(() => codeInputRef.current?.focus(), 50);
    } else if (view === "password") {
      window.setTimeout(() => {
        if (email) {
          passwordInputRef.current?.focus();
        } else {
          emailInputRef.current?.focus();
        }
      }, 50);
    } else if (view === "registerSetPassword") {
      window.setTimeout(() => passwordInputRef.current?.focus(), 50);
    } else if (view === "totp") {
      window.setTimeout(() => totpInputRef.current?.focus(), 50);
    }
  }, [view]); // eslint-disable-line react-hooks/exhaustive-deps

  const emailTrimmed = email.trim();
  const emailOk = React.useMemo(() => {
    const e = emailTrimmed.toLowerCase();
    return e.length >= 3 && e.includes("@") && e.includes(".");
  }, [emailTrimmed]);

  const codeTrimmed = code.trim();
  const codeOk = React.useMemo(() => {
    if (codeTrimmed.length !== 6) return false;
    for (const ch of codeTrimmed) {
      if (ch < "0" || ch > "9") return false;
    }
    return true;
  }, [codeTrimmed]);

  const passwordOk = password.length >= 1;
  const newPasswordOk = newPassword.length >= 10;
  const passwordsMatch = newPassword === confirmPassword;

  // Auto-submit when OTP code reaches 6 valid digits
  React.useEffect(() => {
    if (!codeOk || loading) return;
    if (view === "code") {
      void onVerifyCode();
    } else if (view === "registerCode") {
      void onVerifyRegisterCode();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [codeTrimmed]);

  // Auto-submit TOTP when 6 digits entered (not for backup codes)
  const totpTrimmed = totpCode.trim();
  React.useEffect(() => {
    if (loading || useBackupCode || view !== "totp" || !totpChallengeToken) return;
    if (totpTrimmed.length === 6 && /^\d{6}$/.test(totpTrimmed)) {
      void onVerifyTOTP();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [totpTrimmed]);

  // Sign in with Apple — popup-based redirect flow. Opens Apple's
  // authorization page in a popup, the popup form_posts back to our
  // callback URL, our HTML response postMessages tokens to this window.
  //
  // The popup HTML targets *this* window's origin, and this listener
  // filters incoming messages to a single trusted origin — so a
  // third-party page can't inject a fake success message containing
  // attacker-supplied tokens. HTML is served from the ManyRows API
  // origin (after the OAuth provider redirects the popup back to
  // /auth/{provider}/callback).
  const expectedPopupOrigin = React.useMemo(() => {
    try { return new URL(baseUrl).origin; } catch { return ""; }
  }, [baseUrl]);

  // Track the in-flight popup-flow cleanups (one slot per provider) so
  // an unmount mid-popup doesn't leave a window-level listener (and
  // pending React state updates) floating around.
  const googleCleanupRef = React.useRef<(() => void) | null>(null);
  const appleCleanupRef = React.useRef<(() => void) | null>(null);
  const microsoftCleanupRef = React.useRef<(() => void) | null>(null);
  const githubCleanupRef = React.useRef<(() => void) | null>(null);
  const kakaoCleanupRef = React.useRef<(() => void) | null>(null);
  const naverCleanupRef = React.useRef<(() => void) | null>(null);
  // One generic external-IdP popup at a time; track which slug is busy.
  const [externalLoadingSlug, setExternalLoadingSlug] = React.useState<string | null>(null);
  const externalCleanupRef = React.useRef<(() => void) | null>(null);
  React.useEffect(() => () => {
    googleCleanupRef.current?.();
    appleCleanupRef.current?.();
    microsoftCleanupRef.current?.();
    githubCleanupRef.current?.();
    kakaoCleanupRef.current?.();
    naverCleanupRef.current?.();
    externalCleanupRef.current?.();
  }, []);

  // OAuth popup flow — same logic for all four providers. Opens a popup
  // (synchronously, to avoid pop-up blockers), hits the per-provider
  // /auth/{provider}/authorize endpoint to get a Google/Apple/etc.
  // authorize URL, navigates the popup, then listens for the postMessage
  // from the callback HTML.
  //
  // All four providers route through the writeOAuthCallbackHTML helper
  // server-side, so the postMessage shape is uniform:
  // {type, status, payload}. status >= 400 means the inner handler
  // wrote an error response; the listener turns that into a rejected
  // Promise with an axios-shaped error so extractErrMsg can read it.
  type OAuthProvider = "google" | "apple" | "microsoft" | "github" | "kakao" | "naver";
  type RunOAuthArgs = {
    // Bespoke providers pass `provider`; generic external IdPs pass the
    // explicit name/authorizePath/callbackType overrides instead.
    provider?: OAuthProvider;
    name?: string;
    authorizePath?: string;
    callbackType?: string;
    enabled: boolean;
    setLoading: (b: boolean) => void;
    cleanupRef: React.MutableRefObject<(() => void) | null>;
  };

  const runPopupOAuth = React.useCallback(async (cfg: RunOAuthArgs) => {
    if (!cfg.enabled || !props.appId || !expectedPopupOrigin) return;
    cfg.setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    // Bespoke providers derive these from `provider`; generic external
    // IdPs supply explicit overrides.
    const flowName = cfg.name ?? cfg.provider ?? "oauth";
    const authorizePath = cfg.authorizePath ?? `auth/${cfg.provider}/authorize`;
    const callbackType = cfg.callbackType ?? `${cfg.provider}-oauth-callback`;

    let popup: Window | null = null;
    let listener: ((e: MessageEvent) => void) | null = null;
    let pollInterval: ReturnType<typeof setInterval> | null = null;

    const cleanup = () => {
      if (listener) window.removeEventListener("message", listener);
      if (pollInterval) clearInterval(pollInterval);
      cfg.cleanupRef.current = null;
    };
    cfg.cleanupRef.current = cleanup;

    try {
      // Pre-open the popup synchronously to dodge pop-up blockers; we
      // navigate it once the authorize URL comes back.
      popup = window.open("about:blank", `manyrows-${flowName}-signin`, "width=520,height=640");
      if (!popup) {
        cleanup();
        cfg.setLoading(false);
        return;
      }

      const authzRes = await axios.get<{ url: string }>(
        `${baseUrl}/${authorizePath}`,
        {
          responseType: "json",
          withCredentials: false,
          params: {
            openerOrigin: window.location.origin,
            ...(props.requireConsent ? { consentAccepted: String(consentChecked), consentVersion: props.consentVersion ?? "" } : {}),
          },
        },
      );
      popup.location.href = safePopupUrl(authzRes.data.url);

      const errorTag = `${flowName}_signin_failed`;

      const result = await new Promise<any>((resolve, reject) => {
        listener = (e: MessageEvent) => {
          // Trust only messages from the manyrows API origin (where the
          // callback HTML is served). Anything else is either a stale
          // postMessage from another widget or an injection attempt.
          if (e.origin !== expectedPopupOrigin) return;
          if (popup && e.source !== popup) return;
          if (!e.data || e.data.type !== callbackType) return;
          const payload = e.data.payload;
          if (typeof e.data.status === "number" && e.data.status >= 400) {
            const err: any = new Error(payload?.message || payload?.error || errorTag);
            // Shape it like an axios error so extractErrMsg can read it.
            err.response = { status: e.data.status, data: payload || {} };
            reject(err);
          } else {
            resolve(payload);
          }
        };
        window.addEventListener("message", listener);
        // Detect popup close without a result.
        pollInterval = setInterval(() => {
          if (popup && popup.closed) {
            cleanup();
            reject(new Error("popup_closed"));
          }
        }, 500);
      });

      cleanup();
      try { popup?.close(); } catch { /* ignore */ }

      if (result?.totpRequired && result?.challengeToken) {
        setTotpChallengeToken(result.challengeToken);
        setTotpCode("");
        setUseBackupCode(false);
        setView("totp");
        return;
      }

      if (result?.setupChallengeToken) {
        await enterTOTPSetup(result.setupChallengeToken);
        return;
      }
      if (!result?.accessToken || !result?.refreshToken) {
        throw new Error("Invalid token response");
      }
      props.onTokenPair(result, keepSignedIn);
    } catch (err: any) {
      cleanup();
      try { popup?.close(); } catch { /* ignore */ }
      if (err?.message !== "popup_closed") {
        setErrorMsg(extractErrMsg(err));
      }
    } finally {
      cfg.setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [baseUrl, expectedPopupOrigin, props.appId, keepSignedIn, consentChecked, props.requireConsent, props.consentVersion]);

  const onGoogleClick = () => runPopupOAuth({
    provider: "google",
    enabled: showGoogle,
    setLoading: setGoogleLoading,
    cleanupRef: googleCleanupRef,
  });
  const onAppleClick = () => runPopupOAuth({
    provider: "apple",
    enabled: showApple,
    setLoading: setAppleLoading,
    cleanupRef: appleCleanupRef,
  });
  const onMicrosoftClick = () => runPopupOAuth({
    provider: "microsoft",
    enabled: showMicrosoft,
    setLoading: setMicrosoftLoading,
    cleanupRef: microsoftCleanupRef,
  });
  const onGithubClick = () => runPopupOAuth({
    provider: "github",
    enabled: showGithub,
    setLoading: setGithubLoading,
    cleanupRef: githubCleanupRef,
  });
  const onKakaoClick = () => runPopupOAuth({
    provider: "kakao",
    enabled: showKakao,
    setLoading: setKakaoLoading,
    cleanupRef: kakaoCleanupRef,
  });
  const onNaverClick = () => runPopupOAuth({
    provider: "naver",
    enabled: showNaver,
    setLoading: setNaverLoading,
    cleanupRef: naverCleanupRef,
  });
  const onExternalClick = (slug: string) => runPopupOAuth({
    name: `idp-${slug}`,
    authorizePath: `auth/idp/${slug}/authorize`,
    callbackType: "external-idp-oauth-callback",
    enabled: true,
    setLoading: (b) => setExternalLoadingSlug(b ? slug : null),
    cleanupRef: externalCleanupRef,
  });


  const extractErrMsg = (err: any): string => {
    const status = err?.response?.status;
    const data = err?.response?.data;

    if (typeof data === "string" && data.trim()) return data.trim();

    if (data && typeof data === "object") {
      // Known structured error codes get a user-friendly label rather
      // than leaking the raw "error.xxx" key to the user.
      const code = (data as any).error;
      if (typeof code === "string") {
        const KNOWN_ERROR_LABELS: Record<string, string> = {
          "error.identityConflict": L.identityConflict,
        };
        if (KNOWN_ERROR_LABELS[code]) return KNOWN_ERROR_LABELS[code];
      }

      if (Array.isArray(data.issues) && data.issues.length > 0) {
        const msg = data.issues[0].message;
        if (typeof msg === "string" && msg.trim()) return msg.trim();
      }
      const m =
        (data as any).message ||
        ((data as any).error !== "validation" && (data as any).error) ||
        (data as any).details ||
        (data as any).info ||
        "";
      if (typeof m === "string" && m.trim()) return m.trim();
    }

    if (status === 429) {
      const retryAfter = parseInt(err?.response?.headers?.["retry-after"], 10);
      if (retryAfter > 0) {
        const mins = Math.ceil(retryAfter / 60);
        return L.tooManyRequests.replace("{minutes}", String(mins)).replace("{s}", mins !== 1 ? "s" : "");
      }
      return L.tooManyRequestsGeneric;
    }
    if (status === 401) return L.invalidCredentials;
    if (status === 403) return L.accessDenied;
    if (status) return L.requestFailedWithStatus.replace("{status}", String(status));
    return L.requestFailed;
  };

  // Enter the TOTP setup view from any upstream sign-in step that
  // returned a setup challenge token. Saves the token, clears any
  // stale state, calls /auth/totp/setup-init to fetch the QR / secret,
  // and switches to the totpSetup view. Errors are surfaced via the
  // standard errorMsg banner.
  const enterTOTPSetup = async (challengeToken: string) => {
    setErrorMsg(null);
    setSuccessMsg(null);
    setTotpSetupChallengeToken(challengeToken);
    setTotpSetupSecret("");
    setTotpSetupURI("");
    setTotpSetupCode("");
    setTotpSetupBackupCodes(null);
    setView("totpSetup");
    setLoading(true);
    try {
      const url = baseUrl + "/auth/totp/setup-init";
      const baseConf = { withCredentials: cookieMode, responseType: "json" as const };
      const res = await axios.post<{ secret: string; uri: string }>(
        url,
        { setupChallengeToken: challengeToken },
        baseConf as any,
      );
      setTotpSetupSecret(res.data.secret || "");
      setTotpSetupURI(res.data.uri || "");
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  // Verify the first TOTP code from the new authenticator. On success
  // we receive the real session credentials (token pair) plus backup
  // codes — display the codes once and require explicit ack before
  // handing off to onTokenPair.
  const onSubmitTOTPSetup = async () => {
    const trimmed = totpSetupCode.trim();
    if (loading || !trimmed || !totpSetupChallengeToken) return;
    setErrorMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/totp/setup-complete";
      const baseConf = { withCredentials: cookieMode, responseType: "json" as const };
      const res = await axios.post<any>(
        url,
        { setupChallengeToken: totpSetupChallengeToken, code: trimmed },
        await withDPoPHeader("POST", url, baseConf, { cookieMode }) as any,
      );
      const data = res.data || {};
      // Stash the backup codes for the user to capture before we
      // forward the session to the host app.
      const codes: string[] = Array.isArray(data.backupCodes) ? data.backupCodes : [];
      setTotpSetupBackupCodes(codes);
      const handoff: TokenPairResponse = {
        accessToken: data.accessToken,
        refreshToken: data.refreshToken,
        expiresAt: data.expiresAt,
        expiresIn: data.expiresIn,
      };
      // Defer handoff until the user acks backup codes (see
      // onCompleteTOTPSetupAck). Stash via pendingTokens.
      setPendingTokens(handoff);
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  // After the user has copied / saved their backup codes, finalise
  // the handoff to the host app.
  const onCompleteTOTPSetupAck = () => {
    if (!pendingTokens) return;
    const handoff = pendingTokens;
    setPendingTokens(null);
    setTotpSetupChallengeToken("");
    setTotpSetupSecret("");
    setTotpSetupURI("");
    setTotpSetupCode("");
    setTotpSetupBackupCodes(null);
    props.onTokenPair(handoff, keepSignedIn);
  };

  // OTP Flow: Request code
  const onRequestCode = async () => {
    if (loading || !emailOk) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth";
      const body: any = { email: emailTrimmed };
      if (props.appId) body.appId = props.appId;
      await axios.post(url, body, { withCredentials: false, responseType: "json" } as any);
      try { localStorage.setItem(LAST_EMAIL_KEY, emailTrimmed); } catch {}
      setView("code");
      setSuccessMsg(L.checkEmailForCode);
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  // Magic-link flow: request a one-time sign-in link by email. POST
  // to ManyRows; the link in the email points back at ManyRows;
  // consume redirects to the app URL with tokens in the fragment,
  // picked up by the bootstrap effect above.
  const onRequestMagicLink = async () => {
    if (loading || !emailOk) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/request-magic-link";
      const baseConf = { withCredentials: cookieMode, responseType: "json" as const };
      await axios.post(url, { email: emailTrimmed, rememberMe: keepSignedIn }, baseConf as any);
      try { localStorage.setItem(LAST_EMAIL_KEY, emailTrimmed); } catch {}
      setView("magicLinkSent");
      setSuccessMsg(L.checkEmailForLink);
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  // OTP Flow: Verify code
  const onVerifyCode = async () => {
    if (loading || !emailOk || !codeOk) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/verify";
      const baseConf = { withCredentials: cookieMode, responseType: "json" as const };
      const res = await axios.post<TokenPairResponse>(
        url,
        { email: emailTrimmed, code: codeTrimmed, rememberMe: keepSignedIn },
        await withDPoPHeader("POST", url, baseConf, { cookieMode }) as any
      );
      const data = res.data as any;
      if (data?.totpRequired && data?.challengeToken) {
        setTotpChallengeToken(data.challengeToken);
        setTotpCode("");
        setUseBackupCode(false);
        setView("totp");
        return;
      }
      if (data?.setupChallengeToken) {
        await enterTOTPSetup(data.setupChallengeToken);
        return;
      }
      if (!data?.accessToken || !data?.refreshToken) throw new Error("Invalid token response");
      props.onTokenPair(data, keepSignedIn);
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  // Password Flow
  const onPasswordLogin = async () => {
    if (loading || !emailOk || !passwordOk) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/password";
      const body: any = { email: emailTrimmed, password, rememberMe: keepSignedIn };
      if (props.appId) body.appId = props.appId;

      const baseConf = { withCredentials: cookieMode, responseType: "json" as const };

      const res = await axios.post<any>(
        url,
        body,
        await withDPoPHeader("POST", url, baseConf, { cookieMode }) as any
      );

      try { localStorage.setItem(LAST_EMAIL_KEY, emailTrimmed); } catch {}

      const data = res.data;

      if (data?.totpRequired && data?.challengeToken) {
        setTotpChallengeToken(data.challengeToken);
        setTotpCode("");
        setUseBackupCode(false);
        setView("totp");
        setPassword("");
        setPasswordVisible(false);
        return;
      }

      if (data?.setupChallengeToken) {
        await enterTOTPSetup(data.setupChallengeToken);
        return;
      }
      if (!data?.accessToken || !data?.refreshToken) throw new Error("Invalid token response");

      if (passwordInputRef.current) {
        passwordInputRef.current.value = "";
        passwordInputRef.current.type = "text";
      }

      setPassword("");
      setPasswordVisible(false);
      props.onTokenPair(data, keepSignedIn);
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  // Shared passkey ceremony — used by both the explicit button (mediation
  // "optional") and the conditional-UI effect (mediation "conditional").
  // Conditional UI suspends until the user picks a passkey from the email
  // field's autofill, while optional shows the modal account chooser.
  const runPasskeyLogin = React.useCallback(
    async (mediation: CredentialMediationRequirement, signal?: AbortSignal): Promise<boolean> => {
      const beginUrl = baseUrl + "/auth/passkey/login/begin";
      const finishUrl = baseUrl + "/auth/passkey/login/finish";
      const beginConf = { withCredentials: cookieMode, responseType: "json" as const };

      const beginRes = await axios.post<any>(beginUrl, {}, beginConf as any);
      const { challengeId, publicKeyOptions } = beginRes.data;
      if (!challengeId || !publicKeyOptions) throw new Error("Invalid passkey response");

      const requestOptions = decodeRequestOptions(publicKeyOptions);
      const credential = (await navigator.credentials.get({
        publicKey: requestOptions,
        mediation,
        signal,
      } as CredentialRequestOptions)) as PublicKeyCredential | null;
      if (!credential) return false;

      const finishBody = {
        challengeId,
        rememberMe: keepSignedIn,
        response: encodeAssertionResponse(credential),
      };
      const finishRes = await axios.post<any>(
        finishUrl,
        finishBody,
        await withDPoPHeader("POST", finishUrl, beginConf, { cookieMode }) as any,
      );
      const data = finishRes.data as any;
      if (data?.setupChallengeToken) {
        await enterTOTPSetup(data.setupChallengeToken);
        // Setup view is now mounted inside Auth — don't signal a
        // post-login navigation to the caller. AppKit treats false
        // the same as a cancelled credential prompt: leave the auth
        // UI in place. onTokenPair will fire later from setup-complete.
        return false;
      }
      if (!data?.accessToken || !data?.refreshToken) throw new Error("Invalid token response");
      props.onTokenPair(data, keepSignedIn);
      return true;
    },
    [baseUrl, cookieMode, keepSignedIn, props],
  );

  const onPasskeyLogin = async () => {
    if (loading) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const ok = await runPasskeyLogin("optional");
      if (!ok) {
        // navigator.credentials.get() resolved null — typically because
        // the user has no passkey for this RPID, or dismissed without
        // picking one. Some browsers throw NotAllowedError instead;
        // both surface the same UX-level message.
        setErrorMsg(L.passkeyNotAvailable);
        return;
      }
    } catch (err: any) {
      if (err?.name === "NotAllowedError" || err?.name === "AbortError") {
        setErrorMsg(L.passkeyNotAvailable);
      } else if (err?.response) {
        // axios error from /begin or /finish — extractErrMsg has it
        setErrorMsg(extractErrMsg(err));
      } else if (err?.message) {
        // Plain Error thrown by our own code (e.g. "Invalid passkey
        // response"). extractErrMsg drops err.message for non-axios
        // errors and falls back to a generic string, so surface it
        // directly here instead.
        setErrorMsg(err.message);
      } else {
        setErrorMsg(extractErrMsg(err));
      }
    } finally {
      setLoading(false);
    }
  };

  // Conditional UI: while the email field is on screen, ask the browser to
  // surface registered passkeys as autofill suggestions. The promise sits
  // suspended until the user picks one or we abort. Best-effort — failures
  // are silent because the explicit "Sign in with passkey" button still
  // works.
  React.useEffect(() => {
    if (!props.passkeyEnabled || !isPasskeySupported() || view !== "password") return;
    let cancelled = false;
    const ctrl = new AbortController();

    (async () => {
      try {
        const PKC: any = (window as any).PublicKeyCredential;
        if (typeof PKC?.isConditionalMediationAvailable !== "function") return;
        const available = await PKC.isConditionalMediationAvailable();
        if (!available || cancelled) return;
        await runPasskeyLogin("conditional", ctrl.signal);
      } catch {
        // Conditional UI errors are silent — explicit button is the fallback.
      }
    })();

    return () => {
      cancelled = true;
      ctrl.abort();
    };
  }, [props.passkeyEnabled, view, runPasskeyLogin]);

  // Set Password Flow
  const onRequestSetPasswordCode = async () => {
    if (loading || !emailOk) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/forgot-password";
      const body: any = { email: emailTrimmed };
      if (props.appId) body.appId = props.appId;
      await axios.post(url, body, { withCredentials: cookieMode, responseType: "json" } as any);
      try { localStorage.setItem(LAST_EMAIL_KEY, emailTrimmed); } catch {}
      setView("setPasswordCode");
      setSuccessMsg(L.checkEmailForPasswordResetCode);
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  const onSetPassword = async () => {
    if (loading || !emailOk || !codeOk || !newPasswordOk || !passwordsMatch) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/reset-password";
      const body: any = { email: emailTrimmed, code: codeTrimmed, newPassword, logoutAll };
      if (props.appId) body.appId = props.appId;
      await axios.post(url, body, { withCredentials: cookieMode, responseType: "json" } as any);
      setSuccessMsg(L.passwordSetSuccess);
      setView("password");
      setPassword("");
      setCode("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  const onBackToEmail = () => {
    setView((useOtp || useMagicLink) ? "email" : "password");
    setErrorMsg(null);
    setSuccessMsg(null);
    setCode("");
    setPassword("");
    setNewPassword("");
    setConfirmPassword("");
    setTotpChallengeToken("");
    setTotpCode("");
    setPendingTokens(null);
    props.onScreenChange?.("login");
  };

  // TOTP verify
  const onVerifyTOTP = async () => {
    const trimmed = totpCode.trim();
    if (loading || !trimmed || !totpChallengeToken) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/totp/verify";
      const body: any = { challengeToken: totpChallengeToken, code: trimmed, rememberMe: keepSignedIn };
      if (props.appId) body.appId = props.appId;
      const baseConf = { withCredentials: cookieMode, responseType: "json" as const };
      const res = await axios.post<TokenPairResponse>(
        url,
        body,
        await withDPoPHeader("POST", url, baseConf, { cookieMode }) as any,
      );
      const data = res.data as any;
      if (data?.setupChallengeToken) {
        await enterTOTPSetup(data.setupChallengeToken);
        return;
      }
      if (!data?.accessToken || !data?.refreshToken) throw new Error("Invalid token response");
      props.onTokenPair(data, keepSignedIn);
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  const onGoToSetPassword = () => {
    setView("setPassword");
    setErrorMsg(null);
    setSuccessMsg(null);
    setPassword("");
    props.onScreenChange?.("forgot-password");
  };

  const onGoToRegister = () => {
    // Magic-link mode auto-registers at consume time, so there's no
    // separate sign-up form. Send the user to the email entry view
    // instead — first-time emails create an account on link click.
    if (useMagicLink) {
      setView("email");
      setErrorMsg(null);
      setSuccessMsg(null);
      props.onScreenChange?.("login");
      return;
    }
    setView("register");
    setErrorMsg(null);
    setSuccessMsg(null);
    props.onScreenChange?.("register");
  };

  const onGoToSignIn = () => {
    setView((useOtp || useMagicLink) ? "email" : "password");
    setErrorMsg(null);
    setSuccessMsg(null);
    props.onScreenChange?.("login");
  };

  // Registration Flow
  const onRequestRegisterCode = async () => {
    if (loading || !emailOk || !props.appId) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/register";
      await axios.post(url, { appId: props.appId, email: emailTrimmed }, { withCredentials: false, responseType: "json" } as any);
      try { localStorage.setItem(LAST_EMAIL_KEY, emailTrimmed); } catch {}
      setView("registerCode");
      setSuccessMsg(L.checkEmailForCode);
    } catch (err: any) {
      // 409 + emailAlreadyRegistered: user is trying to sign up with an
      // email that already has an account. Bounce them to the sign-in
      // view with the email pre-filled instead of leaving them staring
      // at an error — much friendlier than the old "silently log in
      // after they verify the OTP, then maybe error on set-password"
      // path.
      const code = err?.response?.data?.error;
      if (err?.response?.status === 409 && code === "error.emailAlreadyRegistered") {
        try { localStorage.setItem(LAST_EMAIL_KEY, emailTrimmed); } catch {}
        setView(useOtp ? "email" : "password");
        setSuccessMsg(null);
        setErrorMsg(extractErrMsg(err));
        props.onScreenChange?.("login");
      } else {
        setErrorMsg(extractErrMsg(err));
      }
    } finally {
      setLoading(false);
    }
  };

  const onVerifyRegisterCode = async () => {
    if (loading || !emailOk || !codeOk || !props.appId) return;
    setErrorMsg(null);
    setSuccessMsg(null);
    setLoading(true);
    try {
      const url = baseUrl + "/auth/verify";
      const baseConf = { withCredentials: cookieMode, responseType: "json" as const };
      const res = await axios.post<TokenPairResponse>(
        url,
        { email: emailTrimmed, code: codeTrimmed, appId: props.appId, rememberMe: keepSignedIn,
          consentAccepted: props.requireConsent ? consentChecked : undefined,
          consentVersion: props.requireConsent ? props.consentVersion : undefined },
        await withDPoPHeader("POST", url, baseConf, { cookieMode }) as any
      );
      const data = res.data as any;
      if (data?.totpRequired && data?.challengeToken) {
        setTotpChallengeToken(data.challengeToken);
        setTotpCode("");
        setUseBackupCode(false);
        setView("totp");
        return;
      }
      if (data?.setupChallengeToken) {
        await enterTOTPSetup(data.setupChallengeToken);
        return;
      }
      if (!data?.accessToken || !data?.refreshToken) throw new Error("Invalid token response");
      // Skip the set-password screen if the verifying user already
      // had a password — common when they thought they were creating
      // an account but actually had one. The set-password POST would
      // 400 ("currentPasswordRequired") and leave them staring at an
      // error while actually being logged in.
      if (showPassword && data?.passwordAlreadySet !== true) {
        setPendingTokens(data);
        setNewPassword("");
        setConfirmPassword("");
        setPasswordVisible(false);
        setErrorMsg(null);
        setSuccessMsg(null);
        setView("registerSetPassword");
      } else {
        props.onTokenPair(data, keepSignedIn);
      }
    } catch (err: any) {
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  const onSetPasswordAfterRegister = async () => {
    if (loading || !pendingTokens || !newPasswordOk || !passwordsMatch) return;
    setErrorMsg(null);
    setLoading(true);
    try {
      // Attach the access token from the verify-step handoff; cookie
      // mode also relies on the freshly-set cookie, so withCredentials
      // tracks cookieMode.
      const conf: any = {
        headers: { Authorization: `Bearer ${pendingTokens.accessToken}` },
        withCredentials: cookieMode,
        responseType: "json",
      };
      await axios.post(baseUrl + "/a/set-password", { password: newPassword }, conf);
      const tokens = pendingTokens;
      setPendingTokens(null);
      props.onTokenPair(tokens, keepSignedIn);
    } catch (err: any) {
      // Keep pendingTokens so the user can correct a rejected password
      // (e.g. server-side "too weak") and retry. Clearing it here orphaned
      // the set-password screen: the button only gates on newPasswordOk /
      // passwordsMatch so it re-enabled, but onSetPasswordAfterRegister's
      // own guard short-circuits on the missing handoff token, leaving the
      // button enabled-but-dead.
      setErrorMsg(extractErrMsg(err));
    } finally {
      setLoading(false);
    }
  };

  const onSkipPasswordSetup = () => {
    if (!pendingTokens) return;
    const tokens = pendingTokens;
    setPendingTokens(null);
    props.onTokenPair(tokens, keepSignedIn);
  };

  // ── Render helpers ──

  const passwordStrength = React.useMemo(() => {
    const pw = newPassword;
    if (!pw) return { score: 0, label: "", color: "" };
    let score = 0;
    if (pw.length >= 10) score++;
    if (pw.length >= 14) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/\d/.test(pw)) score++;
    if (/[^a-zA-Z0-9]/.test(pw)) score++;
    // score: 0-5
    if (pw.length < 10) return { score: 1, label: L.strengthTooShort, color: "var(--ak-color-error)" };
    if (score <= 2) return { score: 2, label: L.strengthWeak, color: "var(--ak-color-error)" };
    if (score <= 3) return { score: 3, label: L.strengthFair, color: "var(--ak-color-warning)" };
    if (score <= 4) return { score: 4, label: L.strengthGood, color: "var(--ak-color-success)" };
    return { score: 5, label: L.strengthStrong, color: "var(--ak-color-success)" };
  }, [newPassword]);

  const renderPasswordStrength = () => {
    if (!newPassword) return null;
    const { score, label, color } = passwordStrength;
    return (
      <div className="ak-stack ak-gap-1" style={{ width: "100%" }}>
        <div style={{ display: "flex", gap: 3 }}>
          {[1, 2, 3, 4, 5].map((i) => (
            <div
              key={i}
              style={{
                flex: 1,
                height: 3,
                borderRadius: 2,
                background: i <= score ? color : "var(--ak-color-divider)",
                transition: "background 0.2s",
              }}
            />
          ))}
        </div>
        <p className="ak-field-helper" style={{ color }}>{label}</p>
      </div>
    );
  };

  const renderPasswordAdornment = () => (
    <div className="ak-field-adornment">
      <button
        type="button"
        className="ak-icon-btn ak-icon-btn-sm"
        onClick={() => setPasswordVisible(!passwordVisible)}
        aria-label={passwordVisible ? "Hide password" : "Show password"}
      >
        <Icon name={passwordVisible ? "eye-slash" : "eye"} size={16} />
      </button>
    </div>
  );

  return (
    <div
      style={
        props.embedded
          ? undefined
          : { minHeight: "100vh", background: "var(--ak-color-bg)", display: "flex", alignItems: "center" }
      }
    >
      <div className="ak-container">
        {props.header}
        <form onSubmit={(e) => e.preventDefault()} autoComplete="on">
        <div className="ak-card">
          <div className="ak-card-content">
            <Collapse show={!!errorMsg}>
              <div className="ak-alert ak-alert-error" role="alert" style={{ marginBottom: 16, borderRadius: 8 }}>
                <span className="ak-alert-content">{errorMsg}</span>
              </div>
            </Collapse>

            <Collapse show={!!successMsg}>
              <div className="ak-alert ak-alert-success" role="alert" style={{ marginBottom: 16, borderRadius: 8 }}>
                <span className="ak-alert-content">{successMsg}</span>
              </div>
            </Collapse>

            {/* PRIMARY SIGN-IN VIEW */}
            <Collapse show={view === "password" || view === "email"}>
              <div className="ak-stack ak-gap-5">
                <h1 className="ak-h5">{L.signInTitle}</h1>

                {showPassword && view === "password" && (
                  <p className="ak-body1 ak-text-secondary" style={{ marginTop: -4 }}>
                    {L.enterEmailAndPassword}
                  </p>
                )}
                {view === "email" && !googleOnly && (
                  <p className="ak-body1 ak-text-secondary" style={{ marginTop: -4 }}>
                    {L.enterEmailForCode}
                  </p>
                )}
                {oauthOnly && (
                  <p className="ak-body1 ak-text-secondary" style={{ marginTop: -4 }}>
                    {L.oauthOnlyPrompt}
                  </p>
                )}

                {/* Password fields */}
                {showPassword && view === "password" && (
                  <>
                    <div className="ak-field">
                      <label className="ak-field-label" htmlFor="ak-email">{L.emailLabel}</label>
                      <input
                        id="ak-email"
                        ref={emailInputRef}
                        className={`ak-field-input${email.length > 0 && !emailOk ? " ak-field-input-error" : ""}`}
                        placeholder={L.emailPlaceholder}
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        autoComplete={props.passkeyEnabled && isPasskeySupported() ? "username webauthn" : "email"}
                        disabled={loading}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            passwordInputRef.current?.focus();
                          }
                        }}
                      />
                    </div>

                    <div className="ak-field">
                      <div className="ak-field-label-row">
                        <label className="ak-field-label" htmlFor="ak-password">{L.passwordLabel}</label>
                        <button
                          type="button"
                          className="ak-btn ak-btn-text ak-btn-sm"
                          onClick={onGoToSetPassword}
                          disabled={loading}
                          style={{ padding: 0 }}
                        >
                          {L.forgotPassword}
                        </button>
                      </div>
                      <div className="ak-field-input-wrap">
                        <input
                          id="ak-password"
                          ref={passwordInputRef}
                          className={`ak-field-input ak-field-input-with-adornment`}
                          placeholder={L.passwordPlaceholder}
                          type={passwordVisible ? "text" : "password"}
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                          autoComplete="current-password"
                          disabled={loading}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.preventDefault();
                              if (!loading && emailOk && passwordOk) void onPasswordLogin();
                            }
                          }}
                        />
                        {renderPasswordAdornment()}
                      </div>
                    </div>

                    <label className="ak-checkbox-label">
                      <input
                        type="checkbox"
                        checked={keepSignedIn}
                        onChange={(e) => setKeepSignedIn(e.target.checked)}
                        disabled={loading}
                      />
                      <span className="ak-body2">{L.keepMeSignedIn}</span>
                    </label>
                  </>
                )}

                {/* OTP email field */}
                {view === "email" && !googleOnly && (
                  <div className="ak-field">
                    <label className="ak-field-label" htmlFor="ak-email-otp">{L.emailLabel}</label>
                    <input
                      id="ak-email-otp"
                      ref={emailInputRef}
                      className={`ak-field-input${email.length > 0 && !emailOk ? " ak-field-input-error" : ""}`}
                      placeholder={L.emailPlaceholder}
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoComplete="email"
                      disabled={loading}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          if (!loading && emailOk) void (useMagicLink ? onRequestMagicLink() : onRequestCode());
                        }
                      }}
                    />
                  </div>
                )}
              </div>
            </Collapse>

            {/* MAGIC-LINK SENT — terminal state for magic-link sign-in.
                Lives outside the email Collapse so the email field can
                animate away while the confirmation message stays put. */}
            <Collapse show={view === "magicLinkSent"}>
              <div className="ak-stack ak-gap-3">
                <button
                  className="ak-btn ak-btn-text"
                  onClick={() => { setSuccessMsg(null); setErrorMsg(null); setView("email"); }}
                  disabled={loading}
                >
                  {L.useDifferentEmail ?? "Use a different email"}
                </button>
              </div>
            </Collapse>

            {/* SET PASSWORD - EMAIL VIEW */}
            <Collapse show={showPassword && view === "setPassword"}>
              <div className="ak-stack ak-gap-5">
                <div className="ak-stack ak-gap-1">
                  <h1 className="ak-h5">{L.setPasswordTitle}</h1>
                  <p className="ak-body1 ak-text-secondary">
                    {L.enterEmailForPasswordCode}
                  </p>
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-email-setpw">{L.emailLabel}</label>
                  <input
                    id="ak-email-setpw"
                    ref={emailInputRef}
                    className={`ak-field-input${email.length > 0 && !emailOk ? " ak-field-input-error" : ""}`}
                    placeholder={L.emailPlaceholder}
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    disabled={loading}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        if (!loading && emailOk) void onRequestSetPasswordCode();
                      }
                    }}
                  />
                </div>
                <button className="ak-btn ak-btn-text ak-btn-sm" onClick={onBackToEmail} disabled={loading} style={{ alignSelf: "flex-start" }}>
                  {L.backToSignIn}
                </button>
              </div>
            </Collapse>

            {/* SET PASSWORD - CODE + NEW PASSWORD VIEW */}
            <Collapse show={showPassword && view === "setPasswordCode"}>
              <div className="ak-stack ak-gap-4 ak-items-center ak-text-center">
                <div className="ak-icon-circle">
                  <Icon name="lock" size={24} />
                </div>
                <div className="ak-stack ak-gap-1">
                  <h1 className="ak-h5" style={{ letterSpacing: -0.3 }}>{L.setYourPasswordTitle}</h1>
                  <p className="ak-body1 ak-text-secondary">
                    {L.weSentCodeTo.split("{email}")[0]}<b>{emailTrimmed || "your email"}</b>{L.weSentCodeTo.split("{email}")[1] || ""}
                  </p>
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-code-setpw">{L.codeLabel}</label>
                  <input
                    id="ak-code-setpw"
                    ref={codeInputRef}
                    className={`ak-field-input${code.length > 0 && !codeOk ? " ak-field-input-error" : ""}`}
                    placeholder={L.codePlaceholder}
                    value={code}
                    onChange={(e) => {
                      const digits = (e.target.value || "").replace(/[^\d]/g, "").slice(0, 6);
                      setCode(digits);
                    }}
                    disabled={loading}
                    inputMode="numeric"
                  />
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-newpw-setpw">{L.newPasswordLabel}</label>
                  <div className="ak-field-input-wrap">
                    <input
                      id="ak-newpw-setpw"
                      className={`ak-field-input ak-field-input-with-adornment${newPassword.length > 0 && !newPasswordOk ? " ak-field-input-error" : ""}`}
                      placeholder={L.newPasswordPlaceholder}
                      type={passwordVisible ? "text" : "password"}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      autoComplete="new-password"
                      disabled={loading}
                    />
                    {renderPasswordAdornment()}
                  </div>
                  {renderPasswordStrength()}
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-confirmpw-setpw">{L.confirmPasswordLabel}</label>
                  <input
                    id="ak-confirmpw-setpw"
                    className={`ak-field-input${confirmPassword.length > 0 && !passwordsMatch ? " ak-field-input-error" : ""}`}
                    placeholder={L.confirmPasswordPlaceholder}
                    type={passwordVisible ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                    disabled={loading}
                  />
                  {confirmPassword.length > 0 && !passwordsMatch && (
                    <p className="ak-field-helper ak-field-helper-error">{L.passwordsDoNotMatch}</p>
                  )}
                </div>
                <label className="ak-checkbox-label" style={{ alignSelf: "flex-start" }}>
                  <input
                    type="checkbox"
                    checked={logoutAll}
                    onChange={(e) => setLogoutAll(e.target.checked)}
                    disabled={loading}
                  />
                  <span className="ak-body2">{L.logOutAllSessions}</span>
                </label>
                <button className="ak-btn ak-btn-text ak-btn-full" disabled={loading} onClick={onBackToEmail} style={{ borderRadius: 8 }}>
                  {L.back}
                </button>
              </div>
            </Collapse>

            {/* OTP CODE VIEW */}
            <Collapse show={view === "code"}>
              <div className="ak-stack ak-gap-4 ak-items-center ak-text-center">
                <div className="ak-icon-circle">
                  <Icon name="envelope" size={24} />
                </div>
                <div className="ak-stack ak-gap-1">
                  <h1 className="ak-h5" style={{ letterSpacing: -0.3 }}>{L.checkYourEmailTitle}</h1>
                  <p className="ak-body1 ak-text-secondary">
                    {L.weSentCodeTo.split("{email}")[0]}<b>{emailTrimmed || "your email"}</b>{L.weSentCodeTo.split("{email}")[1] || ""}
                  </p>
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-otp-code">{L.codeLabel}</label>
                  <input
                    id="ak-otp-code"
                    ref={codeInputRef}
                    className={`ak-field-input${code.length > 0 && !codeOk ? " ak-field-input-error" : ""}`}
                    placeholder={L.codePlaceholder}
                    value={code}
                    onChange={(e) => {
                      const digits = (e.target.value || "").replace(/[^\d]/g, "").slice(0, 6);
                      setCode(digits);
                    }}
                    disabled={loading}
                    inputMode="numeric"
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        if (!loading && codeOk) void onVerifyCode();
                      }
                    }}
                  />
                  {code.length === 0 ? (
                    <p className="ak-field-helper">{L.enterCodeFromEmail}</p>
                  ) : !codeOk ? (
                    <p className="ak-field-helper ak-field-helper-error">{L.codeMustBe6Digits}</p>
                  ) : null}
                </div>
                <button className="ak-btn ak-btn-text ak-btn-full" disabled={loading} onClick={onBackToEmail} style={{ borderRadius: 8 }}>
                  {L.changeEmail}
                </button>
              </div>
            </Collapse>

            {/* REGISTER EMAIL VIEW */}
            <Collapse show={view === "register"}>
              <div className="ak-stack ak-gap-5">
                <div className="ak-stack ak-gap-1">
                  <h1 className="ak-h5">{L.createAccountTitle}</h1>
                  {/* When the app is OAuth-only (primaryAuthMethod
                      "none"), there is no email/code form to register
                      through — sign-up happens via the OAuth buttons
                      below. Skip the "Enter your email…" prompt + the
                      email input that goes with it. */}
                  {!oauthOnly && (
                    <p className="ak-body1 ak-text-secondary">{L.enterEmailToGetStarted}</p>
                  )}
                </div>
                {!oauthOnly && (
                  <div className="ak-field">
                    <label className="ak-field-label" htmlFor="ak-email-register">{L.emailLabel}</label>
                    <input
                      id="ak-email-register"
                      ref={emailInputRef}
                      className={`ak-field-input${email.length > 0 && !emailOk ? " ak-field-input-error" : ""}`}
                      placeholder={L.emailPlaceholder}
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoComplete="email"
                      disabled={loading}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          if (!loading && emailOk) void onRequestRegisterCode();
                        }
                      }}
                    />
                  </div>
                )}
                <button className="ak-btn ak-btn-text ak-btn-sm" onClick={onGoToSignIn} disabled={loading} style={{ alignSelf: "flex-start" }}>
                  {L.alreadyHaveAccount}
                </button>
              </div>
            </Collapse>

            {/* REGISTER CODE VIEW */}
            <Collapse show={view === "registerCode"}>
              <div className="ak-stack ak-gap-4 ak-items-center ak-text-center">
                <div className="ak-icon-circle">
                  <Icon name="envelope" size={24} />
                </div>
                <div className="ak-stack ak-gap-1">
                  <h1 className="ak-h5" style={{ letterSpacing: -0.3 }}>{L.verifyYourEmailTitle}</h1>
                  <p className="ak-body1 ak-text-secondary">
                    {L.weSentCodeTo.split("{email}")[0]}<b>{emailTrimmed || "your email"}</b>{L.weSentCodeTo.split("{email}")[1] || ""}
                  </p>
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-code-register">{L.codeLabel}</label>
                  <input
                    id="ak-code-register"
                    ref={codeInputRef}
                    className={`ak-field-input${code.length > 0 && !codeOk ? " ak-field-input-error" : ""}`}
                    placeholder={L.codePlaceholder}
                    value={code}
                    onChange={(e) => {
                      const digits = (e.target.value || "").replace(/[^\d]/g, "").slice(0, 6);
                      setCode(digits);
                    }}
                    disabled={loading}
                    inputMode="numeric"
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        if (!loading && codeOk && !(props.requireConsent === true && !consentChecked)) void onVerifyRegisterCode();
                      }
                    }}
                  />
                  {code.length === 0 ? (
                    <p className="ak-field-helper">{L.enterCodeFromEmail}</p>
                  ) : !codeOk ? (
                    <p className="ak-field-helper ak-field-helper-error">{L.codeMustBe6Digits}</p>
                  ) : null}
                </div>
                <button
                  className="ak-btn ak-btn-text ak-btn-full"
                  disabled={loading}
                  onClick={() => { setView("register"); setCode(""); setErrorMsg(null); setSuccessMsg(null); }}
                  style={{ borderRadius: 8 }}
                >
                  {L.changeEmail}
                </button>
              </div>
            </Collapse>

            {/* REGISTER SET PASSWORD VIEW */}
            <Collapse show={view === "registerSetPassword"}>
              <div className="ak-stack ak-gap-4 ak-items-center ak-text-center">
                <div className="ak-icon-circle">
                  <Icon name="lock" size={24} />
                </div>
                <div className="ak-stack ak-gap-1">
                  <h1 className="ak-h5" style={{ letterSpacing: -0.3 }}>{L.setAPasswordTitle}</h1>
                  <p className="ak-body1 ak-text-secondary">
                    {L.setPasswordOptional}
                  </p>
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-newpw-register">{L.newPasswordLabel}</label>
                  <div className="ak-field-input-wrap">
                    <input
                      id="ak-newpw-register"
                      ref={passwordInputRef}
                      className={`ak-field-input ak-field-input-with-adornment${newPassword.length > 0 && !newPasswordOk ? " ak-field-input-error" : ""}`}
                      placeholder={L.newPasswordPlaceholder}
                      type={passwordVisible ? "text" : "password"}
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      autoComplete="new-password"
                      disabled={loading}
                    />
                    {renderPasswordAdornment()}
                  </div>
                  {renderPasswordStrength()}
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-confirmpw-register">{L.confirmPasswordLabel}</label>
                  <input
                    id="ak-confirmpw-register"
                    className={`ak-field-input${confirmPassword.length > 0 && !passwordsMatch ? " ak-field-input-error" : ""}`}
                    placeholder={L.confirmPasswordPlaceholder}
                    type={passwordVisible ? "text" : "password"}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    autoComplete="new-password"
                    disabled={loading}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        if (!loading && newPasswordOk && passwordsMatch) void onSetPasswordAfterRegister();
                      }
                    }}
                  />
                  {confirmPassword.length > 0 && !passwordsMatch && (
                    <p className="ak-field-helper ak-field-helper-error">{L.passwordsDoNotMatch}</p>
                  )}
                </div>
                <button className="ak-btn ak-btn-text ak-btn-sm" onClick={onSkipPasswordSetup} disabled={loading}>
                  {L.skipForNow}
                </button>
              </div>
            </Collapse>

            {/* TOTP SETUP VIEW (pre-session enrollment) — shown when an
                upstream sign-in step returned a setupChallengeToken. The
                user enrolls TOTP and verifies their first code; only
                then is a session minted. */}
            <Collapse show={view === "totpSetup"}>
              <div className="ak-stack ak-gap-4">
                <div className="ak-stack ak-gap-1 ak-text-center">
                  <h1 className="ak-h5" style={{ letterSpacing: -0.3 }}>
                    {L.totpSetupTitle ?? "Set up two-factor authentication"}
                  </h1>
                  <p className="ak-body1 ak-text-secondary">
                    {L.totpSetupDesc ?? "This app requires two-factor authentication. Scan the QR with your authenticator app and enter the 6-digit code to finish signing in."}
                  </p>
                </div>
                {totpSetupBackupCodes ? (
                  <div className="ak-stack ak-gap-3">
                    <p className="ak-body1">
                      {L.totpSetupBackupCodesIntro ?? "Save these backup codes somewhere safe. Each code works once if you ever lose your authenticator."}
                    </p>
                    <pre className="ak-code-block" style={{ whiteSpace: "pre-wrap" }}>
                      {totpSetupBackupCodes.join("\n")}
                    </pre>
                    <button
                      className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full"
                      onClick={onCompleteTOTPSetupAck}
                      disabled={!pendingTokens}
                    >
                      {L.totpSetupBackupCodesAck ?? "I've saved my codes — continue"}
                    </button>
                  </div>
                ) : (
                  <>
                    {totpSetupURI ? (
                      <div className="ak-stack ak-gap-3 ak-items-center">
                        <SetupQR uri={totpSetupURI} />
                        {totpSetupSecret && (
                          <div className="ak-w-full">
                            <span className="ak-caption ak-text-secondary ak-font-bold">
                              {L.totpSetupManualKey ?? "Manual entry key"}
                            </span>
                            <div className="ak-code-block">{totpSetupSecret}</div>
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="ak-stack ak-items-center"><Spinner size={24} /></div>
                    )}
                    <div className="ak-field">
                      <label className="ak-field-label" htmlFor="ak-totp-setup-code">
                        {L.codeLabel}
                      </label>
                      <input
                        id="ak-totp-setup-code"
                        className="ak-field-input"
                        placeholder={L.codePlaceholder}
                        value={totpSetupCode}
                        onChange={(e) => setTotpSetupCode((e.target.value || "").replace(/[^\d]/g, "").slice(0, 6))}
                        disabled={loading || !totpSetupURI}
                        inputMode="numeric"
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            e.preventDefault();
                            if (!loading && totpSetupCode.trim() && totpSetupURI) void onSubmitTOTPSetup();
                          }
                        }}
                      />
                    </div>
                  </>
                )}
              </div>
            </Collapse>

            {/* TOTP VERIFY VIEW */}
            <Collapse show={view === "totp"}>
              <div className="ak-stack ak-gap-4 ak-items-center ak-text-center">
                <div className="ak-icon-circle">
                  <Icon name="lock" size={24} />
                </div>
                <div className="ak-stack ak-gap-1">
                  <h1 className="ak-h5" style={{ letterSpacing: -0.3 }}>{L.twoFactorTitle}</h1>
                  <p className="ak-body1 ak-text-secondary">
                    {useBackupCode ? L.enterBackupCode : L.enterTotpCode}
                  </p>
                </div>
                <div className="ak-field">
                  <label className="ak-field-label" htmlFor="ak-totp-code">
                    {useBackupCode ? L.backupCodeLabel : L.codeLabel}
                  </label>
                  <input
                    id="ak-totp-code"
                    ref={totpInputRef}
                    className="ak-field-input"
                    placeholder={useBackupCode ? L.backupCodePlaceholder : L.codePlaceholder}
                    value={totpCode}
                    onChange={(e) => {
                      if (useBackupCode) {
                        setTotpCode(e.target.value);
                      } else {
                        const digits = (e.target.value || "").replace(/[^\d]/g, "").slice(0, 6);
                        setTotpCode(digits);
                      }
                    }}
                    disabled={loading}
                    inputMode={useBackupCode ? undefined : "numeric"}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        if (!loading && totpCode.trim()) void onVerifyTOTP();
                      }
                    }}
                  />
                </div>
                <div className="ak-stack ak-gap-2 ak-w-full">
                  <button
                    className="ak-btn ak-btn-text ak-btn-sm"
                    onClick={() => { setUseBackupCode(!useBackupCode); setTotpCode(""); setErrorMsg(null); }}
                    disabled={loading}
                  >
                    {useBackupCode ? L.useAuthenticatorCode : L.useBackupCode}
                  </button>
                  <button className="ak-btn ak-btn-text ak-btn-sm" onClick={onBackToEmail} disabled={loading}>
                    {L.backToSignIn}
                  </button>
                </div>
              </div>
            </Collapse>
          </div>

          <div className="ak-card-actions" style={{ display: (view === "password" && !showPassword) ? "none" : undefined }}>
            {view === "totpSetup" ? (
              totpSetupBackupCodes ? (
                null
              ) : (
                <button
                  className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full"
                  disabled={loading || !totpSetupCode.trim() || !totpSetupURI}
                  onClick={onSubmitTOTPSetup}
                >
                  {loading ? L.verifying : (L.totpSetupVerify ?? "Verify and finish sign-in")}
                  {loading && <Spinner size={18} white />}
                </button>
              )
            ) : view === "totp" ? (
              <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !totpCode.trim()} onClick={onVerifyTOTP}>
                {loading ? L.verifying : L.verify}
                {loading && <Spinner size={18} white />}
              </button>
            ) : view === "password" ? (
              <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !emailOk || !passwordOk} onClick={onPasswordLogin}>
                {loading ? L.signingIn : L.signIn}
                {loading && <Spinner size={18} white />}
              </button>
            ) : view === "setPassword" && showPassword ? (
              <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !emailOk} onClick={onRequestSetPasswordCode}>
                {loading ? L.sending : L.sendCode}
                {loading && <Spinner size={18} white />}
              </button>
            ) : view === "setPasswordCode" ? (
              <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !codeOk || !newPasswordOk || !passwordsMatch} onClick={onSetPassword}>
                {loading ? L.settingPassword : L.setPassword}
                {loading && <Spinner size={18} white />}
              </button>
            ) : view === "email" ? (
              <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !emailOk} onClick={useMagicLink ? onRequestMagicLink : onRequestCode}>
                {loading ? L.sending : L.continueButton}
                {loading && <Spinner size={18} white />}
              </button>
            ) : view === "magicLinkSent" ? (
              null
            ) : view === "register" ? (
              // OAuth-only: no email-driven register flow, so suppress the
              // Continue button. Sign-up happens via the OAuth row below.
              !oauthOnly ? (
                <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !emailOk || (props.requireConsent === true && !consentChecked)} onClick={onRequestRegisterCode}>
                  {loading ? L.sending : L.continueButton}
                  {loading && <Spinner size={18} white />}
                </button>
              ) : null
            ) : view === "registerCode" ? (
              <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !codeOk || (props.requireConsent === true && !consentChecked)} onClick={onVerifyRegisterCode}>
                {loading ? L.creatingAccount : L.createAccount}
                {loading && <Spinner size={18} white />}
              </button>
            ) : view === "registerSetPassword" ? (
              <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !newPasswordOk || !passwordsMatch} onClick={onSetPasswordAfterRegister}>
                {loading ? L.settingPassword : L.setPassword}
                {loading && <Spinner size={18} white />}
              </button>
            ) : (
              <button className="ak-btn ak-btn-contained ak-btn-lg ak-btn-full" disabled={loading || !codeOk} onClick={onVerifyCode}>
                {loading ? L.verifying : L.signIn}
                {loading && <Spinner size={18} white />}
              </button>
            )}
          </div>

          {/* Alternative sign-in methods (passkey + OAuth) — compact row
              below the primary form. Shown on login (password/email) and
              register; passkey button is suppressed on register because
              passkeys can't sign up — there's no account yet to bind to. */}
          <Collapse show={(view === "password" || view === "email" || view === "register") && (showGoogle || showApple || showMicrosoft || showGithub || showKakao || showNaver || (props.externalIdps != null && props.externalIdps.length > 0) || (view !== "register" && (!!(props.passkeyEnabled && isPasskeySupported()) || showQRSignIn)))}>
            <div className="ak-card-actions">
              <div className="ak-stack ak-gap-4">
                {!googleOnly && (showPassword || view === "email" || view === "register") && (
                  <div className="ak-divider-with-text">
                    <span className="ak-caption ak-text-secondary">{L.orDivider}</span>
                  </div>
                )}

                <div className="ak-oauth-row">
                  {view !== "register" && props.passkeyEnabled && isPasskeySupported() && (
                    <button
                      className="ak-btn ak-btn-outlined"
                      disabled={loading}
                      onClick={onPasskeyLogin}
                      style={{ borderColor: "var(--ak-color-divider)", color: "var(--ak-color-text)" }}
                      aria-label={L.signInWithPasskey}
                    >
                      {loading ? <Spinner size={16} /> : <Icon name="fingerprint" size={16} />}
                      Passkey
                    </button>
                  )}

                  {showGoogle && (
                    <button
                      className="ak-btn ak-btn-outlined"
                      disabled={googleLoading || oauthConsentBlocked}
                      onClick={onGoogleClick}
                      style={{ borderColor: "var(--ak-color-divider)", color: "var(--ak-color-text)" }}
                      aria-label={L.signInWithGoogle}
                    >
                      {googleLoading ? <Spinner size={16} /> : <GoogleIcon />}
                      Google
                    </button>
                  )}

                  {showApple && (
                    <button
                      className="ak-btn ak-btn-outlined"
                      disabled={appleLoading || oauthConsentBlocked}
                      onClick={onAppleClick}
                      style={{ borderColor: "var(--ak-color-divider)", color: "var(--ak-color-text)" }}
                      aria-label={L.signInWithApple}
                    >
                      {appleLoading ? <Spinner size={16} /> : <AppleIcon />}
                      Apple
                    </button>
                  )}

                  {showMicrosoft && (
                    <button
                      className="ak-btn ak-btn-outlined"
                      disabled={microsoftLoading || oauthConsentBlocked}
                      onClick={onMicrosoftClick}
                      style={{ borderColor: "var(--ak-color-divider)", color: "var(--ak-color-text)" }}
                      aria-label={L.signInWithMicrosoft}
                    >
                      {microsoftLoading ? <Spinner size={16} /> : <MicrosoftIcon />}
                      Microsoft
                    </button>
                  )}

                  {showGithub && (
                    <button
                      className="ak-btn ak-btn-outlined"
                      disabled={githubLoading || oauthConsentBlocked}
                      onClick={onGithubClick}
                      style={{ borderColor: "var(--ak-color-divider)", color: "var(--ak-color-text)" }}
                      aria-label={L.signInWithGithub}
                    >
                      {githubLoading ? <Spinner size={16} /> : <GithubIcon />}
                      GitHub
                    </button>
                  )}

                  {showKakao && (
                    <button
                      className="ak-btn ak-btn-outlined"
                      disabled={kakaoLoading || oauthConsentBlocked}
                      onClick={onKakaoClick}
                      style={{ backgroundColor: "#FEE500", borderColor: "#FEE500", color: "rgba(0,0,0,0.85)" }}
                      aria-label={L.signInWithKakao}
                    >
                      {kakaoLoading ? <Spinner size={16} /> : <KakaoIcon />}
                      Kakao
                    </button>
                  )}

                  {showNaver && (
                    <button
                      className="ak-btn ak-btn-outlined"
                      disabled={naverLoading || oauthConsentBlocked}
                      onClick={onNaverClick}
                      style={{ backgroundColor: "#03C75A", borderColor: "#03C75A", color: "#FFFFFF" }}
                      aria-label={L.signInWithNaver}
                    >
                      {naverLoading ? <Spinner size={16} /> : <NaverIcon />}
                      Naver
                    </button>
                  )}

                  {(props.externalIdps ?? []).map((idp) => (
                    <button
                      key={idp.slug}
                      className="ak-btn ak-btn-outlined"
                      disabled={externalLoadingSlug === idp.slug || oauthConsentBlocked}
                      onClick={() => onExternalClick(idp.slug)}
                      style={{ borderColor: "var(--ak-color-divider)", color: "var(--ak-color-text)" }}
                      aria-label={`Sign in with ${idp.displayName}`}
                    >
                      {externalLoadingSlug === idp.slug ? <Spinner size={16} /> : <Icon name={idp.buttonIcon || "key"} size={16} />}
                      {idp.displayName}
                    </button>
                  ))}

                  {view !== "register" && showQRSignIn && (
                    <button
                      className="ak-btn ak-btn-outlined"
                      disabled={loading}
                      onClick={() => {
                        // Navigate to the hosted /qr-sign-in page,
                        // passing the current URL as return_to so
                        // tokens land back here via the magic-link
                        // fragment delivery (mr_session etc.).
                        const url = `${baseUrl}/qr-sign-in?return_to=${encodeURIComponent(window.location.href)}`;
                        window.location.assign(url);
                      }}
                      style={{ borderColor: "var(--ak-color-divider)", color: "var(--ak-color-text)" }}
                      aria-label="Sign in with phone (QR code)"
                    >
                      <Icon name="qrcode" size={16} />
                      Phone
                    </button>
                  )}
                </div>
              </div>
            </div>
          </Collapse>

          {props.requireConsent && view === "register" && (
            <div className="ak-card-actions">
              <label style={{ display: "flex", flexDirection: "row", gap: 8, alignItems: "center", cursor: "pointer" }}>
                <input type="checkbox" checked={consentChecked} onChange={(e) => setConsentChecked(e.target.checked)} style={{ flexShrink: 0 }} />
                <span className="ak-body2">
                  I agree to the{" "}
                  {props.termsUrl ? <a href={props.termsUrl} target="_blank" rel="noopener noreferrer">Terms</a> : "Terms"}
                  {" "}and{" "}
                  {props.privacyUrl ? <a href={props.privacyUrl} target="_blank" rel="noopener noreferrer">Privacy Policy</a> : "Privacy Policy"}
                </span>
              </label>
            </div>
          )}

          {/* Footer band — registration link, or auto-provision hint
              when there's no separate sign-up form to send users to.
              Magic-link and OAuth-only modes both auto-create accounts
              at consume time (link click / provider callback), so a
              "Create account" button just bounces the user back to the
              same email screen — show a hint instead. */}
          {allowRegistration && (view === "password" || view === "email") && (
            <div className="ak-card-footer">
              {oauthOnly ? (
                L.oauthOnlyRegisterHint
              ) : useMagicLink ? (
                L.magicLinkRegisterHint
              ) : (
                <>
                  {L.newHerePrompt}{" "}
                  <button
                    type="button"
                    className="ak-btn ak-btn-text"
                    onClick={onGoToRegister}
                    disabled={loading}
                    style={{ padding: 0, fontWeight: 600 }}
                  >
                    {L.createAccount}
                  </button>
                </>
              )}
            </div>
          )}
        </div>
        </form>

        {!props.hideBranding && (
          <p className="ak-caption ak-text-disabled" style={{ display: "block", marginTop: 8, textAlign: "center" }}>
            Powered by{" "}
            <a
              href="https://manyrows.com"
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: "inherit", textDecoration: "underline" }}
            >
              ManyRows
            </a>
          </p>
        )}
      </div>
    </div>
  );
}
