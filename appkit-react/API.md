# @manyrows/appkit-react API Reference

Version: 1.7.0

---

## Components

### `<AppKit>`

Main wrapper component. Loads the AppKit runtime, renders login UI, and provides context for all hooks.

```tsx
<AppKit workspace="acme" appId="your-app-id">
  {children}
</AppKit>
```

**Props:**

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `workspace` | `string` | **required** | Workspace slug |
| `appId` | `string` | **required** | App ID |
| `baseURL` | `string` | **required** | ManyRows install hostname (e.g. `https://auth.yourdomain.com`) |
| `theme` | `AppKitTheme` | -- | `{ primaryColor?: string; backgroundColor?: string; colorMode?: "light" \| "dark" \| "auto" }` |
| `src` | `string` | `{baseURL}/appkit/assets/appkit.js` | Runtime script URL |
| `integrity` | `string` | -- | Subresource Integrity hash (`sha384-...`) for the runtime script; browser rejects a script whose bytes don't match |
| `timeoutMs` | `number` | `4000` | Script load timeout (ms) |
| `silent` | `boolean` | `false` | Suppress console warnings |
| `throwOnError` | `boolean` | `false` | Throw errors instead of catching |
| `debug` | `boolean` | `false` | Verbose runtime logging |
| `onReady` | `(info: ManyRowsAppKitReady) => void` | -- | Fired when runtime initializes |
| `onError` | `(err: ManyRowsAppKitError) => void` | -- | Fired on errors |
| `onState` | `(snapshot: ManyRowsAppKitSnapshot \| null) => void` | -- | Fired on every state change |
| `onReadyState` | `(snapshot: ManyRowsAppKitSnapshot) => void` | -- | Fired when authenticated |
| `onSignIn` | `(user: AppKitAccount) => void` | -- | Fired when the user becomes signed in (see [Auth event callbacks](#auth-event-callbacks)) |
| `onSignOut` | `() => void` | -- | Fired on a real sign-out (see [Auth event callbacks](#auth-event-callbacks)) |
| `loadAppRuntime` | `boolean` | `false` | Fetch feature flags + config on bootstrap to populate `featureFlags`/`config` on the snapshot. Leave off if you read neither — saves a round trip per page load |
| `className` | `string` | -- | CSS class on wrapper div |
| `style` | `CSSProperties` | -- | Inline styles on wrapper div |
| `containerId` | `string` | auto-generated | DOM ID for runtime container |
| `runtimeMinVersion` | `string` | -- | Minimum runtime version (semver) |
| `runtimeExactVersion` | `string` | -- | Exact runtime version required |
| `loading` | `ReactNode` | -- | Custom loading UI |
| `errorUI` | `(err: ManyRowsAppKitError) => ReactNode` | built-in | Custom error UI |
| `hideLoadingUI` | `boolean` | `false` | Hide default loading indicator |
| `hideErrorUI` | `boolean` | `false` | Hide default error display |
| `publicAccess` | `boolean` | `false` | Always show children regardless of auth state |
| `hideAuthUI` | `boolean` | `false` | Hide the built-in login UI (use with `publicAccess`) |
| `authRoutes` | `Partial<Record<"login" \| "register" \| "forgot-password", string>>` | -- | Map auth screens to URL paths. Auto-derives `initialScreen`, `hideAuthUI`, and `onScreenChange` from the current URL. Partial — omit screens you don't need routable. |
| `authRedirect` | `string` | -- | When set alongside `authRoutes`, automatically navigates to this path after the user authenticates while on an auth route. |
| `initialScreen` | `"login" \| "register" \| "forgot-password"` | -- | Which auth screen to show initially. Derived automatically when using `authRoutes`. |
| `onScreenChange` | `(screen: "login" \| "register" \| "forgot-password") => void` | -- | Called when the user navigates between auth screens (e.g. clicks "Create account"). Derived automatically when using `authRoutes`. |
| `blockLocalhostBaseURLInProd` | `boolean` | `true` | Block localhost URLs in production builds |
| `authHeader` | `ReactNode` | -- | Content rendered above the login/register card |
| `embedded` | `boolean` | `false` | When `true`, the auth form skips its full-viewport wrapper (no `minHeight: 100vh`, no vertical centering, no background) and flows inline in the parent container. Use for sidebars, modals, or inline sections. |
| `labels` | `Record<string, string>` | -- | Override user-facing auth UI text (partial — English defaults for unset keys) |
| `children` | `ReactNode` | -- | Host-side UI (hidden while login screen is active) |

**Label keys** (all optional — English defaults apply):

| Key | Default |
|-----|---------|
| `signInTitle` | `"Sign in"` |
| `setPasswordTitle` | `"Set password"` |
| `setYourPasswordTitle` | `"Set your password"` |
| `checkYourEmailTitle` | `"Check your email"` |
| `createAccountTitle` | `"Create account"` |
| `verifyYourEmailTitle` | `"Verify your email"` |
| `setAPasswordTitle` | `"Set a password"` |
| `twoFactorTitle` | `"Two-factor authentication"` |
| `enterEmailAndPassword` | `"Enter your email and password."` |
| `enterEmailForCode` | `"Enter your email to receive a sign-in code."` |
| `enterEmailForPasswordCode` | `"Enter your email to receive a code for setting your password."` |
| `weSentCodeTo` | `"We sent a 6-digit code to {email}."` |
| `enterEmailToGetStarted` | `"Enter your email to get started."` |
| `setPasswordOptional` | `"Add a password so you can also sign in with email and password. You can skip this for now."` |
| `enterTotpCode` | `"Enter the 6-digit code from your authenticator app."` |
| `enterBackupCode` | `"Enter one of your backup codes."` |
| `emailLabel` | `"Email"` |
| `emailPlaceholder` | `"you@company.com"` |
| `passwordLabel` | `"Password"` |
| `passwordPlaceholder` | `"Enter your password"` |
| `newPasswordLabel` | `"New password"` |
| `newPasswordPlaceholder` | `"At least 10 characters"` |
| `confirmPasswordLabel` | `"Confirm password"` |
| `confirmPasswordPlaceholder` | `"Re-enter your password"` |
| `codeLabel` | `"6-digit code"` |
| `codePlaceholder` | `"123456"` |
| `backupCodeLabel` | `"Backup code"` |
| `backupCodePlaceholder` | `"Enter backup code"` |
| `signInWithGoogle` | `"Sign in with Google"` |
| `signingInWithGoogle` | `"Signing in..."` |
| `signIn` | `"Sign in"` |
| `signingIn` | `"Signing in…"` |
| `forgotPassword` | `"Forgot password?"` |
| `createAccount` | `"Create account"` |
| `continueButton` | `"Continue"` |
| `sending` | `"Sending…"` |
| `sendCode` | `"Send code"` |
| `setPassword` | `"Set password"` |
| `settingPassword` | `"Setting password…"` |
| `verify` | `"Verify"` |
| `verifying` | `"Verifying…"` |
| `creatingAccount` | `"Creating account…"` |
| `backToSignIn` | `"Back to sign in"` |
| `changeEmail` | `"Change email"` |
| `back` | `"Back"` |
| `skipForNow` | `"Skip for now"` |
| `useAuthenticatorCode` | `"Use authenticator code"` |
| `useBackupCode` | `"Use a backup code"` |
| `keepMeSignedIn` | `"Keep me signed in"` |
| `alreadyHaveAccount` | `"Already have an account? Sign in"` |
| `logOutAllSessions` | `"Log out of all other sessions"` |
| `checkEmailForCode` | `"Check your email for a 6-digit code."` |
| `checkEmailForPasswordResetCode` | `"Check your email for a 6-digit code to set your password."` |
| `passwordSetSuccess` | `"Password set successfully! You can now sign in."` |
| `tooManyRequests` | `"Too many requests. Please try again in {minutes} minute{s}."` |
| `tooManyRequestsGeneric` | `"Too many requests. Please wait a bit and try again."` |
| `invalidCredentials` | `"Invalid email or password."` |
| `accessDenied` | `"Access denied."` |
| `accessDeniedNeedAccount` | `"Access denied. You may need to create an account first."` |
| `requestFailed` | `"Request failed."` |
| `requestFailedWithStatus` | `"Request failed ({status})."` |
| `strengthTooShort` | `"Too short"` |
| `strengthWeak` | `"Weak"` |
| `strengthFair` | `"Fair"` |
| `strengthGood` | `"Good"` |
| `strengthStrong` | `"Strong"` |
| `orDivider` | `"or"` |
| `enterCodeFromEmail` | `"Enter the code from the email."` |
| `codeMustBe6Digits` | `"Code must be 6 digits."` |
| `passwordsDoNotMatch` | `"Passwords do not match"` |

Placeholders: `{email}`, `{minutes}`, `{s}`, `{status}` are interpolated at render time. The `"Powered by ManyRows"` branding is not overridable.

---

### `<AppKitAuthed>`

Renders children only when the user is authenticated. Must be inside `<AppKit>`.

```tsx
<AppKitAuthed fallback={<Loading />}>
  <App />
</AppKitAuthed>
```

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `children` | `ReactNode` | **required** | Rendered when authenticated |
| `fallback` | `ReactNode` | `null` | Shown when not authenticated |

---

## Hooks

### `useAppKit()`

Access the full AppKit context. Must be called inside `<AppKit>`.

**Returns: `AppKitContextValue`**

```typescript
{
  status: "idle" | "loading" | "mounted" | "error";
  error: ManyRowsAppKitError | null;
  readyInfo: ManyRowsAppKitReady | null;
  snapshot: ManyRowsAppKitSnapshot | null;
  isAuthenticated: boolean;
  handle: ManyRowsAppKitHandle | null;

  // Convenience methods (safe no-ops if runtime not loaded)
  refresh(): void;
  logout(): Promise<void>;
  setToken(tok: string | null): void;
  destroy(): void;
  info(): ManyRowsAppKitReady | null;
  showProfile(): void;   // open the built-in account-management dialog
  hideProfile(): void;
}
```

---

### `useUser()`

Returns the current user's account, or `null` if not authenticated.

**Returns: `AppKitAccount | null`**

```typescript
{
  id: string;
  email: string;
  name?: string;                         // display name (falls back to email)
  metadata?: Record<string, unknown>;    // admin-managed (ManyRows console)
  appMetadata?: Record<string, unknown>; // app-managed (server API)
}
```

---

### `useRoles()`

Returns the user's role names for the current app.

**Returns: `string[]`**

---

### `usePermissions()`

Returns the user's permission keys for the current app.

**Returns: `string[]`**

---

### `usePermission(permission: string)`

Check if the user has a specific permission.

**Returns: `boolean`**

---

### `useRole(role: string)`

Check if the user has a specific role.

**Returns: `boolean`**

---

### `useFeatureFlags()`

Returns all feature flags for the current environment.

**Returns: `AppKitFeatureFlag[]`**

```typescript
{ key: string; enabled: boolean }[]
```

---

### `useFeatureFlag(key: string)`

Check if a specific feature flag is enabled.

**Returns: `boolean`**

---

### `useConfig()`

Returns all public config values for the current environment.

**Returns: `AppKitConfigValue[]`**

```typescript
{ key: string; type: string; value?: unknown }[]
```

---

### `useConfigValue<T>(key: string, fallback?: T)`

Get a single config value by key, with an optional fallback.

**Returns: `T | undefined`**

---

### `useToken()`

Returns the current JWT access token, or `null`.

**Returns: `string | null`**

---

### `useAuthFetch()`

Returns a `fetch`-compatible function that automatically includes the Bearer token in the `Authorization` header. Use this for making authenticated API calls to your own backend.

**Returns: `(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>`**

```tsx
const authFetch = useAuthFetch();

// Works just like fetch, but with auth headers added
const res = await authFetch("/api/favourites");
const data = await res.json();

// POST with body
await authFetch("/api/items", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ name: "New item" }),
});
```

The returned function is memoized and updates when the token changes.

---

### `useUpdateProfile()`

Returns a function to update the current user's profile (e.g. display name). Takes an object for future extensibility.

**Returns: `(update: { displayName: string }) => Promise<void>`**

```tsx
const updateProfile = useUpdateProfile();
await updateProfile({ displayName: "Jane Doe" });
```

---

### `useSetPassword()`

Returns a function to change the signed-in user's password. Pass `currentPassword` for the change-password path — required whenever the user already has a password set.

**Returns: `(params: { password: string; currentPassword?: string }) => Promise<void>`**

```tsx
const setPassword = useSetPassword();
await setPassword({ password: "newPw1234567", currentPassword: "oldPw" });
```

**OAuth-only / passkey-only users (no password ever set)** can't use this hook to install an initial password — the server gates that path on a recent email-OTP at this app (`error.passwordSetRequiresOTP`) so a stolen access token can't silently install a backdoor password. Drive those users through AppKit's `<Auth>` Profile dialog's password tab, which performs the `/auth/forgot-password` → `/auth/reset-password` ceremony.

---

### `useTheme()`

Access the resolved color mode and semantic color tokens. Use this to style custom components in a way that adapts to light/dark mode.

**Returns: `ThemeContextValue`**

```typescript
{
  colorMode: "light" | "dark";   // resolved mode (never "auto")
  tokens: ColorTokens;           // semantic color strings
}
```

**Key tokens:**

| Token | Description |
|-------|-------------|
| `surfacePrimary` | Card/modal backgrounds |
| `surfaceSecondary` | Drop zones, secondary panels |
| `surfaceTertiary` | Skeleton loaders, meta pills |
| `textPrimary` | Headings, body text |
| `textSecondary` | Labels, descriptions |
| `textTertiary` | Hints, timestamps |
| `borderDefault` | Input/card borders |
| `borderSubtle` | Dividers, separators |
| `primary` | Accent color (buttons, links) |
| `primarySubtle` | Selected/active backgrounds |
| `error` | Error text/icons |
| `success` | Success text/icons |
| `warning` | Warning text/icons |

```tsx
import { useTheme } from "@manyrows/appkit-react";

function MyCard({ children }) {
  const { tokens } = useTheme();
  return (
    <div style={{
      backgroundColor: tokens.surfacePrimary,
      color: tokens.textPrimary,
      border: `1px solid ${tokens.borderDefault}`,
    }}>
      {children}
    </div>
  );
}
```

---

### `useOrganization()`

Returns the session's active organization, or `null` when there is none (a user in no orgs, or an app without organizations enabled).

**Returns: `AppKitOrganization | null`**

```tsx
const org = useOrganization();
if (org) return <p>Acting in {org.name} ({org.orgRole})</p>;
```

---

### `useOrganizationList()`

Returns every organization the user belongs to (for a switcher). Empty when the user belongs to none or the app doesn't have organizations enabled.

**Returns: `AppKitOrganization[]`**

---

### `useSetActiveOrganization()`

Returns a function that switches the session's active organization. On success it refreshes the snapshot (roles/permissions/active-org re-resolve for the new org) and resolves with the new active organization. Throws if the user is not an active member of the target org.

**Returns: `(orgId: string) => Promise<AppKitOrganization>`**

```tsx
const setActiveOrganization = useSetActiveOrganization();
await setActiveOrganization(org.id);
```

---

### `useCreateOrganization()`

Returns a function to create an organization (self-serve). The app must have `org_creation_policy = self_serve`; otherwise the server rejects with `error.forbidden`. The creator is seeded as the owner. Refreshes the snapshot so the new org appears in `useOrganizationList()`.

**Returns: `(params: { name: string; slug?: string }) => Promise<AppKitCreatedOrganization>`**

```tsx
const createOrg = useCreateOrganization();
const org = await createOrg({ name: "Acme" });
```

---

### `useRenameOrganization()`

Returns a function to rename an organization (owner/admin). Refreshes the snapshot.

**Returns: `(orgId: string, params: { name?: string; slug?: string }) => Promise<void>`**

---

### `useArchiveOrganization()`

Returns a function to archive an organization (owner-only; reversible operator-side). Refreshes the snapshot.

**Returns: `(orgId: string) => Promise<void>`**

---

### `useOrganizationMembers()`

Returns a function that fetches a page of an organization's members (any active member may read), plus the total match count. Not part of the snapshot — call it on demand. `pageSize` defaults to 50 (capped at 200 server-side).

**Returns: `(orgId: string, opts?: AppKitOrgListParams) => Promise<AppKitOrganizationMemberPage>`**

```tsx
const listMembers = useOrganizationMembers();
const { members, total } = await listMembers(org.id, { page: 0, search: "jane" });
```

---

### `useSetOrganizationMember()`

Returns a function to change a member's tier and/or project roles (owner/admin). Pass either field. Demoting the last owner rejects with `error.conflict`.

**Returns: `(orgId: string, userId: string, params: { orgRole?: string; roleIds?: string[] }) => Promise<void>`**

---

### `useRemoveOrganizationMember()`

Returns a function to remove a member, or leave the org (pass your own user id). Removing someone else needs owner/admin; the last owner can't be removed (`error.conflict`).

**Returns: `(orgId: string, userId: string) => Promise<void>`**

---

### `useOrganizationInvites()`

Returns a function that fetches a page of an organization's pending invites (owner/admin), plus the total match count. `pageSize` defaults to 50 (capped at 200).

**Returns: `(orgId: string, opts?: AppKitOrgListParams) => Promise<AppKitOrganizationInvitePage>`**

---

### `useCreateOrganizationInvite()`

Returns a function to invite an email to the organization (owner/admin). The app must have an App URL configured for the accept link.

**Returns: `(orgId: string, params: { email: string; orgRole?: string; roleIds?: string[] }) => Promise<AppKitOrganizationInvite>`**

```tsx
const invite = useCreateOrganizationInvite();
await invite(org.id, { email: "jane@acme.com", orgRole: "member" });
```

---

### `useRevokeOrganizationInvite()`

Returns a function to revoke a pending invite (owner/admin).

**Returns: `(orgId: string, inviteId: string) => Promise<void>`**

---

### `useSessions()`

Returns a function that fetches the user's active sessions across devices. The session making the request has `current: true`.

**Returns: `() => Promise<AppKitSession[]>`**

```tsx
const listSessions = useSessions();
const sessions = await listSessions();
const thisMachine = sessions.find((s) => s.current);
```

---

### `useRevokeSession()`

Returns a function that revokes one of the user's sessions (signs out that device). The current session (`current: true`) cannot be revoked this way — the server rejects it; use `logout()` from `useAppKit()` instead.

**Returns: `(sessionId: string) => Promise<void>`**

```tsx
const revokeSession = useRevokeSession();
await revokeSession(session.id);
```

---

### `useRevokeOtherSessions()`

Returns a function that revokes all of the user's **other** sessions in one call ("log out everywhere else"). The current session stays signed in — call `logout()` from `useAppKit()` to end it too. Resolves with the number of sessions revoked.

**Returns: `() => Promise<{ revoked: number }>`**

```tsx
const revokeOtherSessions = useRevokeOtherSessions();
const { revoked } = await revokeOtherSessions();
```

---

### `usePasskeys()`

Returns a function that lists the user's registered passkeys.

**Returns: `() => Promise<AppKitPasskey[]>`**

```tsx
const listPasskeys = usePasskeys();
const passkeys = await listPasskeys();
```

---

### `useRenamePasskey()`

Returns a function that renames a passkey.

**Returns: `(passkeyId: string, params: { name: string }) => Promise<void>`**

```tsx
const renamePasskey = useRenamePasskey();
await renamePasskey(passkey.id, { name: "Work laptop" });
```

---

### `useDeletePasskey()`

Returns a function that deletes a passkey. A sensitive operation — pass `{ password }` or `{ code }` (request one with `useRequestReauthCode()`). The re-auth proof travels in the DELETE request body; any proxy in front of the ManyRows server must forward DELETE bodies.

**Returns: `(passkeyId: string, reauth?: AppKitReauthParams) => Promise<void>`**

```tsx
const deletePasskey = useDeletePasskey();
await deletePasskey(passkey.id, { password });
```

---

### `useRegisterPasskey()`

Returns a function that registers a new passkey for the signed-in user by running the full WebAuthn ceremony: fetches a challenge, prompts the browser (`navigator.credentials.create`), and stores the credential. Resolves with the new `AppKitPasskey`.

Throws `"Passkeys are not supported in this browser"` when WebAuthn is unavailable. On user cancellation or prompt timeout the thrown error has `name === PASSKEY_CANCELLED` — detect it with `isPasskeyCancelled(err)`. When the authenticator already holds a passkey for this account (the server sends `excludeCredentials` and the browser raises `InvalidStateError`) the thrown error has `name === PASSKEY_ALREADY_REGISTERED` — detect it with `isPasskeyAlreadyRegistered(err)`. Only one ceremony can run at a time; disable the trigger element while the returned promise is pending.

**Returns: `(params?: { name?: string }) => Promise<AppKitPasskey>`**

```tsx
import { useRegisterPasskey, isPasskeyCancelled } from "@manyrows/appkit-react";

const registerPasskey = useRegisterPasskey();
try {
  const passkey = await registerPasskey({ name: "MacBook" });
  console.log("Registered:", passkey.id);
} catch (err) {
  if (!isPasskeyCancelled(err)) throw err;
}
```

---

### `useStartTOTPSetup()`

Returns a function that begins TOTP enrollment. A sensitive operation — pass `{ password }` or `{ code }` (see `useRequestReauthCode`). Resolves with `{ secret, uri }` where `secret` is the base32 key for manual entry and `uri` is an `otpauth://` URL to render as a QR code. Calling this again before enabling discards the previous pending secret (any earlier QR code stops working). Rejects with `error.totpAlreadyEnabled` when 2FA is already active.

**Returns: `(reauth: AppKitReauthParams) => Promise<AppKitTOTPSetup>`**

```tsx
const startTOTPSetup = useStartTOTPSetup();
const { secret, uri } = await startTOTPSetup({ password });
// render uri as a QR code, show secret for manual entry
```

---

### `useEnableTOTP()`

Returns a function that completes TOTP enrollment by verifying a code from the authenticator app. Resolves with `{ backupCodes }` — show them to the user once; they are not retrievable later (only regenerable via `useRegenerateBackupCodes`). Refreshes the snapshot.

**Returns: `(params: { code: string }) => Promise<{ backupCodes: string[] }>`**

```tsx
const enableTOTP = useEnableTOTP();
const { backupCodes } = await enableTOTP({ code: totpCode });
// display backupCodes to user — they will not be shown again
```

---

### `useDisableTOTP()`

Returns a function that disables TOTP. A sensitive operation — pass `{ password }` or `{ code }` (see `useRequestReauthCode`). Refreshes the snapshot.

**Returns: `(reauth: AppKitReauthParams) => Promise<void>`**

```tsx
const disableTOTP = useDisableTOTP();
await disableTOTP({ password });
```

---

### `useRegenerateBackupCodes()`

Returns a function that regenerates the user's TOTP backup codes, invalidating the old set. Unlike the other sensitive hooks, this endpoint accepts the password only — there is no email-code path.

**Returns: `(params: { password: string }) => Promise<{ backupCodes: string[] }>`**

```tsx
const regenerateBackupCodes = useRegenerateBackupCodes();
const { backupCodes } = await regenerateBackupCodes({ password });
```

---

### `useIdentities()`

Returns a function that lists the user's linked sign-in identities (OAuth providers / external IdPs).

**Returns: `() => Promise<AppKitIdentity[]>`**

```tsx
const listIdentities = useIdentities();
const identities = await listIdentities(); // [{ provider: "google", ... }]
```

---

### `useDisconnectIdentity()`

Returns a function that unlinks a sign-in identity by provider name. Disconnecting always succeeds — the server keeps no last-method guard because every user can recover via the email-based flows. Add your own confirmation UX.

**Returns: `(provider: string) => Promise<void>`**

```tsx
const disconnectIdentity = useDisconnectIdentity();
await disconnectIdentity("google");
```

---

### `useDeleteAccount()`

Returns a function that permanently deletes the signed-in user's account at this app, then signs them out. Requires the account password. Rejects with `error.forbidden` when the app has account deletion disabled.

**Returns: `(params: { password: string }) => Promise<void>`**

```tsx
const deleteAccount = useDeleteAccount();
await deleteAccount({ password });
// user is signed out automatically on success
```

---

### `useRequestEmailChange()`

Returns a function that starts an email change. The server sends a 6-digit verification code to **both** the current (old) address and the new address. Complete the change with `useVerifyEmailChange`, passing both codes. Requires the current password.

**Returns: `(params: { newEmail: string; password: string }) => Promise<void>`**

```tsx
const requestEmailChange = useRequestEmailChange();
await requestEmailChange({ newEmail: "new@example.com", password });
```

---

### `useVerifyEmailChange()`

Returns a function that completes a pending email change. The request step emails a 6-digit code to **both** the current (old) address and the new address — the old-address code approves the change; the new-address code proves inbox ownership. Pass both. Refreshes the snapshot so `useUser()` reflects the new email.

**Returns: `(params: { oldCode: string; newCode: string }) => Promise<void>`**

```tsx
const verifyEmailChange = useVerifyEmailChange();
await verifyEmailChange({ oldCode: "222333", newCode: "123456" });
```

---

### `useUserFields()`

Returns a function that fetches the user's client-visible custom fields with their current values.

**Returns: `() => Promise<AppKitUserField[]>`**

```tsx
const getFields = useUserFields();
const fields = await getFields(); // [{ key, type, label, value }]
```

---

### `useUpdateUserFields()`

Returns a function that updates the user's custom fields. Pass a flat `key → value` map (e.g. `{ plan: "team" }`), **not** the `AppKitUserField[]` array returned by `useUserFields()`. Only client-writable fields are accepted. Resolves with the updated field list.

**Returns: `(values: Record<string, unknown>) => Promise<AppKitUserField[]>`**

```tsx
const updateFields = useUpdateUserFields();
const updated = await updateFields({ displayPronouns: "they/them" });
```

---

### `useRequestReauthCode()`

Returns a function that emails the signed-in user a 6-digit verification code. Use it before sensitive hooks (`useStartTOTPSetup`, `useDisableTOTP`, `useDeletePasskey`) for users who have no password (OAuth-only / passkey-only) — pass the received code as `{ code }` in `AppKitReauthParams`.

**Returns: `() => Promise<void>`**

**Re-authentication pattern:**

```tsx
const requestReauthCode = useRequestReauthCode();
const disableTOTP = useDisableTOTP();

// Password user:
await disableTOTP({ password });

// Passwordless (OAuth/passkey-only) user:
await requestReauthCode();               // emails a 6-digit code
await disableTOTP({ code: enteredCode }); // user types the code
```

---

## Auth event callbacks

Two props on `<AppKit>` notify the host when the user's auth state changes:

| Prop | Type | Description |
|------|------|-------------|
| `onSignIn` | `(user: AppKitAccount) => void` | Fired when the user becomes signed in |
| `onSignOut` | `() => void` | Fired when the signed-in user becomes signed out |

**`onSignIn`** fires on a fresh login **and** when an existing session resolves after the component mounts. A remount re-fires it for the same session — if your handler has side effects (analytics, redirects) guard against duplicates with a ref. It is **not** fired while the runtime is in the transient `"checking"` state.

**`onSignOut`** fires only on a real sign-out (logout, session revocation, token expiry). It is **not** fired when the initial state resolves to unauthenticated.

```tsx
<AppKit
  workspace="acme"
  appId="your-app-id"
  baseURL="https://auth.yourdomain.com"
  onSignIn={(user) => {
    analytics.identify(user.id);
  }}
  onSignOut={() => {
    analytics.reset();
  }}
>
  <App />
</AppKit>
```

---

## Types

### `ManyRowsAppKitError`

```typescript
{
  code: ManyRowsAppKitErrorCode;
  message: string;
  details?: unknown;
}
```

**Error codes:**
- `RUNTIME_NOT_FOUND` -- runtime global not found after script loaded
- `SCRIPT_LOAD_FAILED` -- script tag failed to load
- `SCRIPT_TIMEOUT` -- runtime not available within `timeoutMs`
- `RUNTIME_ERROR` -- runtime reported an error
- `RUNTIME_VERSION_MISMATCH` -- exact version check failed
- `RUNTIME_VERSION_TOO_OLD` -- minimum version check failed
- `BASE_URL_NOT_ALLOWED_IN_PROD` -- localhost baseURL in production build
- `INVALID_PROPS` -- missing or invalid required props

### `ManyRowsAppKitReady`

```typescript
{
  container: HTMLElement;
  containerId?: string;
  workspace: string;
  appId: string;
  baseURL: string;
  version: string;
}
```

### `ManyRowsAppKitSnapshot`

```typescript
{
  status: "checking" | "authenticated" | "unauthenticated";
  jwtToken: string | null;
  appData: AppKitAppData | null;
  workspaceBaseURL: string;
  appBaseURL: string;
  appId: string;
  app: {
    id: string;
    name: string;
    workspaceSlug: string;
    workspaceName: string;
    allowRegistration: boolean;
    primaryAuthMethod?: "password" | "code" | "magicLink" | "none";
    googleOAuthClientId?: string;
    hideBranding?: boolean;
    require2fa?: boolean;
  } | null;
}
```

### `AppKitAppData`

```typescript
{
  account?: AppKitAccount;
  workspaceSlug: string;
  workspaceName: string;
  hasAppAccess: boolean;
  roles: string[];
  permissions: string[];
  featureFlags?: AppKitFeatureFlag[];   // populated when loadAppRuntime is set
  config?: AppKitConfigValue[];         // populated when loadAppRuntime is set
  // Active organization, or null when there is none. Absent (undefined)
  // when the app doesn't have organizations enabled.
  organization?: AppKitOrganization | null;
  // Every organization the user belongs to. Absent when the orgs feature
  // is off; [] when enabled but the user belongs to none.
  organizations?: AppKitOrganization[];
}
```

### `AppKitOrganization`

```typescript
{
  id: string;
  name: string;
  slug: string;
  orgRole: string;     // the user's tier in this org: owner | admin | member
}
```

### `AppKitOrganizationRole`

A project (app RBAC) role assigned to an organization membership.

```typescript
{ id: string; slug: string; name: string }
```

### `AppKitOrganizationMember`

```typescript
{
  userId: string;
  email: string;
  orgRole: string;     // tier: owner | admin | member
  status: string;
  roles: AppKitOrganizationRole[];
}
```

### `AppKitOrganizationInvite`

```typescript
{
  id: string;
  email: string;
  orgRole: string;
  status: string;
  invitedByEmail?: string;
  createdAt: string;   // ISO 8601
  expiresAt: string;   // ISO 8601
}
```

### `AppKitCreatedOrganization`

```typescript
{ id: string; name: string; slug: string; status: string }
```

### `AppKitOrgListParams`

Pagination + search options for the member/invite listings.

```typescript
{
  page?: number;       // 0-based page index
  pageSize?: number;   // default 50, capped at 200 server-side
  search?: string;     // case-insensitive email substring filter
}
```

### `AppKitOrganizationMemberPage` / `AppKitOrganizationInvitePage`

```typescript
{ members: AppKitOrganizationMember[]; total: number; page: number; pageSize: number }
{ invites: AppKitOrganizationInvite[]; total: number; page: number; pageSize: number }
```

### `AppKitSession`

```typescript
{
  id: string;
  createdAt: string;       // ISO 8601
  lastSeenAt: string;      // ISO 8601
  userAgent?: string;
  ip?: string;
  current: boolean;        // true for the session making the request
}
```

### `AppKitPasskey`

```typescript
{
  id: string;
  name?: string;
  transports: string[];
  aaguid?: string;
  authenticatorName?: string;
  backupEligible: boolean;
  backupState: boolean;
  createdAt: string;       // ISO 8601
  lastUsedAt?: string;     // ISO 8601
}
```

### `AppKitIdentity`

```typescript
{
  provider: string;        // e.g. "google"
  providerEmail?: string;
  createdAt: string;       // ISO 8601
  lastLoginAt: string;     // ISO 8601
}
```

### `AppKitUserField`

```typescript
{
  key: string;
  type: string;
  label: string;
  value?: unknown;
}
```

### `AppKitReauthParams`

An exclusive union — pass exactly one of `password` or `code`:

```typescript
| { password: string; code?: never }
| { code: string; password?: never }
```

Used by `useStartTOTPSetup`, `useDisableTOTP`, and `useDeletePasskey`. For passwordless users (OAuth-only / passkey-only), request an email code with `useRequestReauthCode()` then pass `{ code }`.

### `AppKitTOTPSetup`

```typescript
{
  secret: string;   // base32 secret for manual entry
  uri: string;      // otpauth:// URL — render as a QR code
}
```

### `PASSKEY_CANCELLED` / `isPasskeyCancelled`

```typescript
/** Error name on the error thrown when the user dismisses the passkey prompt. */
const PASSKEY_CANCELLED: "PasskeyRegistrationCancelled";

/** Returns true when an error came from the user dismissing the passkey prompt. */
function isPasskeyCancelled(e: unknown): boolean;
```

### `PASSKEY_ALREADY_REGISTERED` / `isPasskeyAlreadyRegistered`

```typescript
/** Error name when the authenticator already holds a passkey for this account. */
const PASSKEY_ALREADY_REGISTERED: "PasskeyAlreadyRegistered";

/** Returns true when registration failed because the authenticator is already enrolled. */
function isPasskeyAlreadyRegistered(e: unknown): boolean;
```

---

### `isPasskeySupported()`

`isPasskeySupported(): boolean` — returns `true` when the browser supports WebAuthn; use it to decide whether to render passkey UI at all.

```tsx
import { isPasskeySupported } from "@manyrows/appkit-react";

{isPasskeySupported() && <AddPasskeyButton />}
```

---

### `ManyRowsAppKitHandle`

Imperative API for advanced control. Available via `useAppKit().handle`.

```typescript
{
  version: string;
  info(): ManyRowsAppKitReady | null;
  getState(): ManyRowsAppKitSnapshot | null;
  subscribe(fn: (s: ManyRowsAppKitSnapshot | null) => void): () => void;
  refresh(): void;
  logout(): Promise<void>;
  setToken(tok: string | null): void;
  // Optional — absent on older runtime versions; the useAppKit()
  // convenience methods guard both calls.
  showProfile?: () => void;
  hideProfile?: () => void;
  destroy(): void;
}
```
