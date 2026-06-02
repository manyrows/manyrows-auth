# @manyrows/appkit-react API Reference

Version: 0.1.9

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
| `theme` | `AppKitTheme` | -- | `{ primaryColor?: string; colorMode?: "light" \| "dark" \| "auto" }` |
| `src` | `string` | `{baseURL}/appkit/assets/appkit.js` | Runtime script URL |
| `timeoutMs` | `number` | `4000` | Script load timeout (ms) |
| `silent` | `boolean` | `false` | Suppress console warnings |
| `throwOnError` | `boolean` | `false` | Throw errors instead of catching |
| `onReady` | `(info: ManyRowsAppKitReady) => void` | -- | Fired when runtime initializes |
| `onError` | `(err: ManyRowsAppKitError) => void` | -- | Fired on errors |
| `onState` | `(snapshot: ManyRowsAppKitSnapshot \| null) => void` | -- | Fired on every state change |
| `onReadyState` | `(snapshot: ManyRowsAppKitSnapshot) => void` | -- | Fired when authenticated |
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

### `<ImageUploader>`

Drag-and-drop image upload component with progress bar.

```tsx
<ImageUploader
  onUpload={() => console.log("done")}
  onError={(err) => console.error(err)}
/>
```

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `onUpload` | `() => void` | -- | Called after successful upload |
| `onError` | `(error: string) => void` | -- | Called on upload error |
| `defaultTitle` | `string` | -- | Pre-fill title field |
| `defaultDescription` | `string` | -- | Pre-fill description field |
| `variants` | `string` | -- | CSV of variant names to generate |
| `showFields` | `boolean` | `true` | Show title/description fields |
| `showVariantPicker` | `boolean` | `false` | Show variant picker UI |
| `accept` | `string` | `"image/png,image/jpeg,image/gif,image/webp,image/avif"` | Accepted MIME types |
| `maxSize` | `number` | `4194304` (4 MB) | Max file size in bytes |
| `refType` | `string` | -- | Reference type tag |
| `refId` | `string` | -- | Reference ID tag |
| `visibility` | `"private" \| "shared"` | `"private"` | Visibility: `private` (only uploader) or `shared` (all app users) |
| `label` | `string` | -- | Custom label text |
| `disabled` | `boolean` | `false` | Disable the uploader |
| `className` | `string` | -- | CSS class |
| `style` | `CSSProperties` | -- | Inline styles |

---

### `<ImagePicker>`

Browsable image grid with search, pagination, and selection.

```tsx
<ImagePicker
  onSelect={(img) => setSelected(img)}
  selectedImageId={selected?.imageId}
  columns={4}
  pageSize={12}
/>
```

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `onSelect` | `(image: ImageResource) => void` | -- | Called when an image is clicked |
| `onClose` | `() => void` | -- | Called when picker is dismissed (modal mode) |
| `mode` | `"modal" \| "inline"` | `"inline"` | Display mode |
| `pageSize` | `number` | `20` | Images per page |
| `showSearch` | `boolean` | `true` | Show search input |
| `searchPlaceholder` | `string` | -- | Placeholder for search input |
| `selectedImageId` | `string` | -- | Highlight this image |
| `columns` | `number` | `4` | Grid columns |
| `showActions` | `boolean` | `false` | Show edit/delete actions per image |
| `refType` | `string` | -- | Filter by reference type |
| `refId` | `string` | -- | Filter by reference ID |
| `visibility` | `"private" \| "shared"` | -- | Filter by visibility |
| `refreshSignal` | `number` | -- | Increment to trigger refetch |
| `className` | `string` | -- | CSS class |
| `style` | `CSSProperties` | -- | Inline styles |

---

### `<ImageDetails>`

Detail view for a single image showing metadata and variants.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `image` | `ImageResource` | **required** | Image to display |
| `onClose` | `() => void` | **required** | Close handler |
| `onEdit` | `(image: ImageResource) => void` | -- | Edit handler |
| `onDelete` | `(image: ImageResource) => void` | -- | Delete handler |
| `className` | `string` | -- | CSS class |
| `style` | `CSSProperties` | -- | Inline styles |

---

### `<MrImage>`

Responsive image component with automatic variant selection and signed URLs.

```tsx
<MrImage image={img} variant="w800" alt="Photo" />
```

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `image` | `ImageResource` | **required** | Image resource |
| `variant` | `string` | -- | Specific variant name (e.g. `"orig"`, `"sq200"`, `"w800"`) |
| `width` | `number` | -- | Display width |
| `height` | `number` | -- | Display height |
| `alt` | `string` | -- | Alt text |
| `loading` | `"lazy" \| "eager"` | `"lazy"` | Loading strategy |
| `objectFit` | `CSSProperties["objectFit"]` | `"cover"` | CSS object-fit |
| `sizes` | `string` | -- | `srcset` sizes attribute |
| `onLoad` | `() => void` | -- | Image loaded callback |
| `onError` | `() => void` | -- | Image error callback |
| `className` | `string` | -- | CSS class |
| `style` | `CSSProperties` | -- | Inline styles |

---

### `<FileUploader>`

Drag-and-drop file upload component with progress bar.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `onUpload` | `() => void` | -- | Called after successful upload |
| `onError` | `(error: string) => void` | -- | Called on upload error |
| `defaultTitle` | `string` | -- | Pre-fill title field |
| `defaultDescription` | `string` | -- | Pre-fill description field |
| `showFields` | `boolean` | `true` | Show title/description fields |
| `accept` | `string` | common doc types | Accepted file extensions |
| `maxSize` | `number` | `10485760` (10 MB) | Max file size in bytes |
| `refType` | `string` | -- | Reference type tag |
| `refId` | `string` | -- | Reference ID tag |
| `visibility` | `"private" \| "shared"` | `"private"` | Visibility: `private` (only uploader) or `shared` (all app users) |
| `label` | `string` | -- | Custom label text |
| `disabled` | `boolean` | `false` | Disable the uploader |
| `className` | `string` | -- | CSS class |
| `style` | `CSSProperties` | -- | Inline styles |

---

### `<FilePicker>`

Browsable file list with search, pagination, and selection.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `onSelect` | `(file: FileResource) => void` | -- | Called when a file is clicked |
| `onClose` | `() => void` | -- | Called when picker is dismissed (modal mode) |
| `mode` | `"modal" \| "inline"` | `"inline"` | Display mode |
| `pageSize` | `number` | `20` | Files per page |
| `showSearch` | `boolean` | `true` | Show search input |
| `searchPlaceholder` | `string` | -- | Placeholder for search input |
| `selectedFileId` | `string` | -- | Highlight this file |
| `showActions` | `boolean` | `false` | Show edit/delete actions per file |
| `refType` | `string` | -- | Filter by reference type |
| `refId` | `string` | -- | Filter by reference ID |
| `visibility` | `"private" \| "shared"` | -- | Filter by visibility |
| `refreshSignal` | `number` | -- | Increment to trigger refetch |
| `className` | `string` | -- | CSS class |
| `style` | `CSSProperties` | -- | Inline styles |

---

### `<FileDetails>`

Detail view for a single file showing metadata.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `file` | `FileResource` | **required** | File to display |
| `onClose` | `() => void` | **required** | Close handler |
| `onEdit` | `(file: FileResource) => void` | -- | Edit handler |
| `onDelete` | `(file: FileResource) => void` | -- | Delete handler |
| `className` | `string` | -- | CSS class |
| `style` | `CSSProperties` | -- | Inline styles |

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
}
```

---

### `useUser()`

Returns the current user's account, or `null` if not authenticated.

**Returns: `AppKitAccount | null`**

```typescript
{
  email: string;
  name: string;
  metadata: Record<string, any>;      // set by workspace admins
  appMetadata: Record<string, any>;   // set by the app
}
```

---

### `useProject()`

Returns the current project access info, or `null`.

**Returns: `AppKitProjectAccess | null`**

```typescript
{
  name: string;
  roles: string[];
  permissions: string[];
}
```

---

### `useRoles()`

Returns the user's role names for the current project.

**Returns: `string[]`**

---

### `usePermissions()`

Returns the user's permission keys for the current project.

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
{ key: string; type: string; value?: any }[]
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

### `useMetadata()`

Returns the admin-managed metadata for the current user.

**Returns: `Record<string, any>`**

---

### `useAppMetadata()`

Returns the app-managed metadata for the current user.

**Returns: `Record<string, any>`**

---

### `useUpdateAppMetadata()`

Returns a function to patch the user's app metadata.

**Returns: `(patch: Record<string, any>) => Promise<void>`**

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

### `useImages(opts?)`

List images with pagination and search.

**Options:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `page` | `number` | `1` | Current page |
| `pageSize` | `number` | `20` | Items per page |
| `q` | `string` | -- | Search query |
| `refType` | `string` | -- | Filter by reference type |
| `refId` | `string` | -- | Filter by reference ID |
| `visibility` | `"private" \| "shared"` | -- | Filter by visibility |
| `enabled` | `boolean` | `true` | Enable/disable fetching |

**Returns:**

```typescript
{
  images: ImageResource[];
  page: number;
  pageSize: number;
  total: number;
  pageCount: number;
  loading: boolean;
  error: string | null;
  refetch(): void;
  setPage(page: number): void;
  setQuery(q: string): void;
  available: boolean;              // false if image service not configured
  removeImage(imageId: string): Promise<void>;
  updateImage(imageId: string, opts: ImageUpdateOptions): Promise<void>;
}
```

---

### `useImage(imageId: string | null | undefined, opts?)`

Fetch a single image by ID.

**Options:** `{ enabled?: boolean }`

**Returns:**

```typescript
{
  image: ImageResource | null;
  loading: boolean;
  error: string | null;
  refetch(): void;
  available: boolean;
}
```

---

### `useImageUpload()`

Programmatic image upload with progress tracking.

**Returns:**

```typescript
{
  upload(opts: ImageUploadOptions): Promise<void>;
  cancel(): void;
  progress: UploadProgress;
  reset(): void;
  available: boolean;
}
```

**`ImageUploadOptions`:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | `File` | yes | File to upload |
| `title` | `string` | yes | Image title |
| `description` | `string` | no | Image description |
| `variants` | `string` | no | CSV of variant names to generate |
| `refType` | `string` | no | Reference type tag |
| `refId` | `string` | no | Reference ID tag |
| `visibility` | `"private" \| "shared"` | no | Visibility (`"private"` default, `"shared"` for all app users) |

---

### `useFiles(opts?)`

List files with pagination and search. Same options as `useImages` (including `visibility`).

**Returns:**

```typescript
{
  files: FileResource[];
  page: number;
  pageSize: number;
  total: number;
  pageCount: number;
  loading: boolean;
  error: string | null;
  refetch(): void;
  setPage(page: number): void;
  setQuery(q: string): void;
  available: boolean;
  removeFile(fileId: string): Promise<void>;
  updateFile(fileId: string, opts: FileUpdateOptions): Promise<void>;
}
```

---

### `useFile(fileId: string | null | undefined, opts?)`

Fetch a single file by ID.

**Options:** `{ enabled?: boolean }`

**Returns:**

```typescript
{
  file: FileResource | null;
  loading: boolean;
  error: string | null;
  refetch(): void;
  available: boolean;
}
```

---

### `useFileUpload()`

Programmatic file upload with progress tracking.

**Returns:**

```typescript
{
  upload(opts: FileUploadOptions): Promise<void>;
  cancel(): void;
  progress: UploadProgress;
  reset(): void;
  available: boolean;
}
```

**`FileUploadOptions`:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | `File` | yes | File to upload |
| `title` | `string` | yes | File title |
| `description` | `string` | no | File description |
| `refType` | `string` | no | Reference type tag |
| `refId` | `string` | no | Reference ID tag |
| `visibility` | `"private" \| "shared"` | no | Visibility (`"private"` default, `"shared"` for all app users) |

---

## Types

### `ImageResource`

```typescript
{
  imageId: string;
  title: string;
  description: string;
  originalName: string;
  uploadedAt: string;           // ISO 8601
  uploadedBy?: string;
  visibility: string;           // "private" | "shared"
  refType?: string;
  refId?: string;
  variants: ImageVariant[];
}
```

### `ImageVariant`

```typescript
{
  id: string;
  variant: string;              // e.g. "orig", "sq200", "w800"
  s3Key: string;
  content_type: string;
  format: string;
  size_bytes: number;
  sha256_hex: string;
  ext: string;
  width: number;
  height: number;
  etag: string;
  versionId: string;
  objectURL: string;            // signed URL
  expiresAt: string;            // ISO 8601
}
```

### `FileResource`

```typescript
{
  fileId: string;
  title: string;
  description: string;
  originalName: string;
  contentType: string;
  format: string;               // e.g. "pdf", "docx"
  sizeBytes: number;
  ext: string;
  objectURL: string;            // signed URL
  expiresAt: string;            // ISO 8601
  uploadedAt: string;
  uploadedBy?: string;
  visibility: string;           // "private" | "shared"
  refType?: string;
  refId?: string;
}
```

### `UploadProgress`

```typescript
{
  status: "idle" | "uploading" | "success" | "conflict" | "error";
  progress: number;             // 0-100
  bytesUploaded: number;
  bytesTotal: number;
  error: string | null;
  existingImageId?: string;     // set when status is "conflict"
  existingFileId?: string;      // set when status is "conflict"
}
```

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
  appId: string;
  app: {
    id: string;
    name: string;
    workspaceSlug: string;
    workspaceName: string;
    allowRegistration: boolean;
    authMethodPassword?: boolean;
    googleOAuthClientId?: string;
  } | null;
}
```

### `AppKitAppData`

```typescript
{
  account?: AppKitAccount;
  workspaceSlug: string;
  workspaceName: string;
  projectAccess: boolean;
  project?: AppKitProjectAccess;
  featureFlags?: AppKitFeatureFlag[];
  config?: AppKitConfigValue[];
}
```

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
  destroy(): void;
}
```
