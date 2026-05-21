import * as React from "react";
import axios from "axios";
import type { Product, Workspace, Role } from "../core.ts";
import { extractApiError } from "../lib/apiError.ts";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  FormControl,
  FormControlLabel,
  IconButton,
  InputLabel,
  MenuItem,
  Radio,
  RadioGroup,
  Select,
  Stack,
  Switch,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { ChevronDown, Copy, Plus, Trash2 } from "lucide-react";
import Eyebrow from "../components/Eyebrow.tsx";
import PageHeader from "../components/PageHeader.tsx";
import Loader from "../Loader.tsx";
import StatusChip from "../components/StatusChip.tsx";
import SaveBar from "../components/SaveBar.tsx";

export type App = {
  id: string;
  workspaceId: string;
  productId: string;
  type: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  enabled: boolean;
  allowRegistration: boolean;
  allowAccountDeletion?: boolean;
  allowEmailChange?: boolean;
  defaultRoleId?: string;
  allowedEmailDomains?: string[];
  primaryAuthMethod: "password" | "code" | "magicLink" | "none";
  appUrl?: string;
  authDomain?: string;
  authMethodGoogle: boolean;
  googleOAuthClientId?: string;
  googleOAuthRedirectUri?: string;
  hasGoogleClientSecret?: boolean;
  authMethodApple?: boolean;
  appleServicesId?: string;
  appleTeamId?: string;
  appleKeyId?: string;
  appleOAuthRedirectUri?: string;
  hasApplePrivateKey?: boolean;
  authMethodMicrosoft?: boolean;
  microsoftClientId?: string;
  microsoftTenant?: string;
  microsoftOAuthRedirectUri?: string;
  hasMicrosoftClientSecret?: boolean;
  authMethodGithub?: boolean;
  githubClientId?: string;
  githubOAuthRedirectUri?: string;
  hasGithubClientSecret?: boolean;
  require2fa: boolean;
  passwordMinLength: number;
  passwordMinZxcvbnScore: number;
  cookieDomain?: string | null;
  sessionTtlMinutes?: number | null;
  idleTimeoutMinutes?: number | null;
  rememberMeTtlMinutes?: number | null;
  accessTokenTtlMinutes?: number | null;
  maxSessionsPerUser?: number | null;
  transportMode?: "local" | "cookie";
  sessionCookieSameSite?: "lax" | "strict";
  qrSignInEnabled?: boolean;
  // Server-computed QR sign-in URL (AppBaseURL + workspace slug +
  // app id + /qr-sign-in). Present whenever BASE_URL is pinned.
  qrSignInUrl?: string;
};

type RolesResponse = { roles: Role[] };

// Re-export from the shared helper so existing consumers keep working.
export const errText = extractApiError;

interface Props {
  project: Product;
  workspace: Workspace;
  appId: string;
}


export default function AppAuthMethods({ project, appId }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const [loading, setLoading] = React.useState(true);
  const [app, setApp] = React.useState<App | null>(null);
  const [roles, setRoles] = React.useState<Role[]>([]);
  const [tab, setTab] = React.useState(0);

  const appsBaseURL = `/admin/workspace/${project.workspaceId}/products/${project.id}/apps`;
  const rolesURL = `/admin/workspace/${project.workspaceId}/products/${project.id}/roles`;

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    Promise.all([
      axios.get<App>(`${appsBaseURL}/${appId}/`),
      axios.get<RolesResponse>(rolesURL).catch(() => ({ data: { roles: [] } })),
    ])
      .then(([appRes, rolesRes]) => {
        if (!alive) return;
        setApp(appRes.data);
        setRoles(rolesRes.data?.roles || []);
        setLoading(false);
      })
      .catch((e) => {
        if (!alive) return;
        setLoading(false);
        enqueueSnackbar(errText(e), { variant: "error" });
      });
    return () => { alive = false; };
  }, [appId, appsBaseURL, rolesURL, enqueueSnackbar]);

  if (loading) return <Loader />;
  if (!app) return null;

  const cardURL = `${appsBaseURL}/${app.id}`;
  const onSaved = (updated: App) => setApp(updated);
  const onError = (e: unknown) => enqueueSnackbar(errText(e), { variant: "error" });
  const onSuccess = () => enqueueSnackbar(t("apps.appUpdated"), { variant: "success" });

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 3 }}>
      <PageHeader title={t("app.nav.authMethods", { defaultValue: "Auth methods" })} mb={0} />

      <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Tabs
          value={tab}
          onChange={(_, v) => setTab(v)}
          variant="scrollable"
          scrollButtons="auto"
          allowScrollButtonsMobile
          sx={{
            minHeight: 40,
            "& .MuiTab-root": {
              textTransform: "uppercase",
              minHeight: 40,
              py: 1,
              px: 1.75,
              transition: "background-color 120ms ease",
              "&:hover": {
                backgroundColor: "action.hover",
              },
            },
          }}
        >
          <Tab label={t("apps.tab.general", { defaultValue: "General" })} />
          <Tab label={t("apps.tab.email", { defaultValue: "Email" })} />
          <Tab label={t("apps.tab.oauth", { defaultValue: "OAuth" })} />
          <Tab label={t("apps.tab.passkeys", { defaultValue: "Passkeys" })} />
          <Tab label={t("apps.tab.oidc", { defaultValue: "OIDC" })} />
          <Tab label={t("apps.tab.qr", { defaultValue: "QR sign-in" })} />
        </Tabs>
      </Box>

      <Box sx={{ minWidth: 0 }}>
        {tab === 0 && (
          <GeneralCard
            app={app} roles={roles} cardURL={cardURL}
            onSaved={onSaved} onSuccess={onSuccess} onError={onError}
          />
        )}
        {tab === 1 && (
          <PrimaryAuthMethodCard
            app={app} cardURL={cardURL}
            onSaved={onSaved} onSuccess={onSuccess} onError={onError}
          />
        )}
        {tab === 2 && (
          <OAuthProvidersList
            app={app} cardURL={cardURL}
            onSaved={onSaved} onSuccess={onSuccess} onError={onError}
          />
        )}
        {tab === 3 && (
          <PasskeysCard appsBaseURL={appsBaseURL} appId={app.id} />
        )}
        {tab === 4 && (
          <OIDCProviderCard
            app={app} cardURL={cardURL}
            onSaved={onSaved} onSuccess={onSuccess} onError={onError}
          />
        )}
        {tab === 5 && (
          <QRSignInCard
            app={app} cardURL={cardURL}
            onSaved={onSaved} onSuccess={onSuccess} onError={onError}
          />
        )}
      </Box>
    </Box>
  );
}

export type CardProps = {
  app: App;
  cardURL: string;
  onSaved: (a: App) => void;
  onSuccess: () => void;
  onError: (e: unknown) => void;
};

// =====================================================================
// General - self-registration + cross-cutting 2FA policy
// =====================================================================

function GeneralCard(props: CardProps & { roles: Role[] }) {
  const { app, roles, cardURL, onSaved, onSuccess, onError } = props;
  const { t } = useTranslation();

  const [allowRegistration, setAllowRegistration] = React.useState(app.allowRegistration);
  // Default true preserves the existing AppKit behavior for apps
  // created before this flag existed (the migration also defaults
  // the column to true, so once those apps are touched in any way
  // the value rounds back to a real boolean).
  const [allowAccountDeletion, setAllowAccountDeletion] = React.useState(app.allowAccountDeletion ?? true);
  const [allowEmailChange, setAllowEmailChange] = React.useState(app.allowEmailChange ?? true);
  const [defaultRoleId, setDefaultRoleId] = React.useState(app.defaultRoleId || "");
  const [allowedDomains, setAllowedDomains] = React.useState((app.allowedEmailDomains || []).join(", "));
  const [require2fa, setRequire2fa] = React.useState(!!app.require2fa);
  const [saving, setSaving] = React.useState(false);

  // Default role is optional; flipping the toggle no longer mutates
  // the selection. Self-registered users without a default role land
  // with zero roles and the customer backend decides what their token
  // can do.
  const handleAllowRegistrationChange = (next: boolean) => {
    setAllowRegistration(next);
  };

  // resetFromApp re-applies the saved app state to local form state.
  // Used both on app prop changes (after a successful save) and as the
  // Discard handler in the floating save bar.
  const resetFromApp = React.useCallback(() => {
    setAllowRegistration(app.allowRegistration);
    setAllowAccountDeletion(app.allowAccountDeletion ?? true);
    setAllowEmailChange(app.allowEmailChange ?? true);
    setDefaultRoleId(app.defaultRoleId || "");
    setAllowedDomains((app.allowedEmailDomains || []).join(", "));
    setRequire2fa(!!app.require2fa);
  }, [app]);

  React.useEffect(() => { resetFromApp(); }, [resetFromApp]);

  const dirty =
    allowRegistration !== app.allowRegistration ||
    allowAccountDeletion !== (app.allowAccountDeletion ?? true) ||
    allowEmailChange !== (app.allowEmailChange ?? true) ||
    defaultRoleId !== (app.defaultRoleId || "") ||
    allowedDomains !== (app.allowedEmailDomains || []).join(", ") ||
    require2fa !== !!app.require2fa;

  async function save() {
    setSaving(true);
    try {
      const domains = allowedDomains.split(",").map((d) => d.trim().toLowerCase()).filter((d) => d.length > 0);
      const body = {
        allowRegistration,
        allowAccountDeletion,
        allowEmailChange,
        defaultRoleId: allowRegistration && defaultRoleId ? defaultRoleId : null,
        allowedEmailDomains: domains,
        require2fa,
      };
      const res = await axios.put<App>(`${cardURL}/registration`, body);
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Stack
      // No outer Paper wrapper - sections separate themselves with
      // hairline dividers instead of a card frame. Single-column.
      divider={<Box sx={{ height: "1px", bgcolor: "divider", my: 1 }} />}
      spacing={3.5}
      sx={{ maxWidth: 680 }}
    >
      <Section
        overline={t("apps.sectionOverline.authentication", { defaultValue: "Authentication" })}
        title={t("apps.selfRegistration", { defaultValue: "Self-registration" })}
        desc={t("apps.dialog.allowRegDesc")}
      >
        <FormControlLabel
          control={<Switch checked={allowRegistration} onChange={(e) => handleAllowRegistrationChange(e.target.checked)} disabled={saving} />}
          label={
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {t("apps.dialog.allowRegLabel")}
            </Typography>
          }
          sx={{ ml: 0 }}
        />
        {allowRegistration && (
          <Stack spacing={1.5} sx={{ pl: 5.5, mt: 0.5 }}>
            <FormControl fullWidth size="small" disabled={saving}>
              <InputLabel id="reg-default-role-label" shrink>{t("apps.dialog.defaultRoleLabel")}</InputLabel>
              <Select
                labelId="reg-default-role-label"
                label={t("apps.dialog.defaultRoleLabel")}
                value={defaultRoleId}
                displayEmpty
                onChange={(e) => setDefaultRoleId(String(e.target.value))}
              >
                <MenuItem value="">
                  <em>{t("apps.dialog.defaultRoleNone", { defaultValue: "No default role" })}</em>
                </MenuItem>
                {roles.map((r) => (
                  <MenuItem key={r.id} value={r.id}>{r.name} ({r.slug})</MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              size="small"
              fullWidth
              label={t("apps.dialog.allowedDomains")}
              value={allowedDomains}
              onChange={(e) => setAllowedDomains(e.target.value)}
              disabled={saving}
              placeholder={t("apps.dialog.allowedDomainsPlaceholder")}
              helperText={t("apps.dialog.allowedDomainsHelper")}
            />
          </Stack>
        )}
      </Section>

      <Section
        overline={t("apps.sectionOverline.accountSecurity", { defaultValue: "Account security" })}
        title={t("apps.twoFactor", { defaultValue: "Two-factor authentication" })}
        desc={t("apps.twoFactorDesc", { defaultValue: "Cross-cutting policy that applies to every sign-in method on this app." })}
      >
        <FormControlLabel
          control={<Switch checked={require2fa} onChange={(e) => setRequire2fa(e.target.checked)} disabled={saving} />}
          label={
            <Stack spacing={0}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.require2fa", { defaultValue: "Require two-factor authentication" })}</Typography>
              <Typography variant="caption" color="text.secondary">{t("apps.require2faDesc", { defaultValue: "Users without TOTP set up will be forced to configure it before accessing the app." })}</Typography>
            </Stack>
          }
          sx={{ alignItems: "flex-start", ml: 0 }}
        />
      </Section>

      <Section
        overline={t("apps.sectionOverline.endUserControls", { defaultValue: "End-user controls" })}
        title="Account deletion"
        desc="Controls whether end users can delete their own account from the AppKit profile dialog. Disable when you want to keep audit trails intact and route deletions through support."
      >
        <FormControlLabel
          control={<Switch checked={allowAccountDeletion} onChange={(e) => setAllowAccountDeletion(e.target.checked)} disabled={saving} />}
          label={
            <Stack spacing={0}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>Allow users to delete their own account</Typography>
              <Typography variant="caption" color="text.secondary">
                When off, the "Delete account" button is hidden and the server rejects deletion requests with{" "}
                <Box component="code" sx={{ fontFamily: "var(--font-mono)", fontSize: 11.5, px: 0.5, py: "1px", bgcolor: "action.hover", border: "1px solid", borderColor: "divider", borderRadius: 0.5 }}>403</Box>.
              </Typography>
            </Stack>
          }
          sx={{ alignItems: "flex-start", ml: 0 }}
        />
      </Section>

      <Section
        overline={t("apps.sectionOverline.endUserControls", { defaultValue: "End-user controls" })}
        title={
          <Stack direction="row" alignItems="center" spacing={1}>
            <Typography sx={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" }}>
              Email change
            </Typography>
            <Chip
              label="Advanced"
              size="small"
              sx={{
                height: 18,
                fontSize: 9.5,
                fontWeight: 600,
                letterSpacing: "0.08em",
                fontFamily: "var(--font-mono)",
                textTransform: "uppercase",
                color: "warning.dark",
                bgcolor: "rgba(201,122,26,0.08)",
                border: "1px solid rgba(201,122,26,0.25)",
              }}
            />
          </Stack>
        }
        desc={
          <>
            When on, AppKit's profile dialog shows a "Change Email Address" block; the user enters their current password + new address, receives a verification code at the new address, and the change applies on confirm. When off, the block is hidden and the server rejects email-change requests with{" "}
            <Box component="code" sx={{ fontFamily: "var(--font-mono)", fontSize: 11.5, px: 0.5, py: "1px", bgcolor: "action.hover", border: "1px solid", borderColor: "divider", borderRadius: 0.5 }}>403</Box>.
          </>
        }
      >
        <Alert
          severity="warning"
          icon={false}
          sx={{
            fontSize: 12.5,
            borderLeft: "3px solid",
            borderLeftColor: "warning.main",
            borderRadius: "0 8px 8px 0",
            lineHeight: 1.6,
            "& .MuiAlert-message": { py: 0.5 },
          }}
        >
          <Typography
            component="span"
            sx={{
              display: "inline-flex",
              alignItems: "center",
              fontFamily: "var(--font-mono)",
              textTransform: "uppercase",
              letterSpacing: "0.12em",
              fontSize: 10,
              fontWeight: 600,
              color: "warning.dark",
              mr: 1,
            }}
          >
            Recommended: leave off
          </Typography>
          Email is usually the canonical identity tying your audit logs and support tickets to a user - letting end users rewrite it from the profile dialog breaks that link and creates support headaches. Only enable when you have a specific reason (e.g. internal tool where users routinely change addresses).
          {" "}
          <strong>Only applies when email/password sign-in is on</strong> - the change-email flow needs a current password to confirm, so it's hidden automatically in <em>code</em> or <em>OAuth-only</em> mode regardless of this toggle.
        </Alert>
        <FormControlLabel
          control={<Switch checked={allowEmailChange} onChange={(e) => setAllowEmailChange(e.target.checked)} disabled={saving} />}
          label={
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              Allow users to update their email address
            </Typography>
          }
          sx={{ ml: 0 }}
        />
      </Section>

      <SaveBar
        dirty={dirty}
        saving={saving}
        onSave={save}
        onDiscard={resetFromApp}
      />
    </Stack>
  );
}

// =====================================================================
// Email-form mode - tri-state. Picks how the email field on the
// sign-in screen behaves: password, sign-in code (OTP), or hidden.
// =====================================================================

type PrimaryAuthMethod = "password" | "code" | "magicLink" | "none";

function PrimaryAuthMethodCard({ app, cardURL, onSaved, onSuccess, onError }: CardProps) {
  const { t } = useTranslation();

  const [primaryAuthMethod, setPrimaryAuthMethod] = React.useState<PrimaryAuthMethod>(app.primaryAuthMethod);
  const [saving, setSaving] = React.useState(false);

  const resetFromApp = React.useCallback(() => {
    setPrimaryAuthMethod(app.primaryAuthMethod);
  }, [app]);

  React.useEffect(() => { resetFromApp(); }, [resetFromApp]);

  const dirty = primaryAuthMethod !== app.primaryAuthMethod;

  // Magic-link mode requires an App URL - the email contains a link
  // that has to point at a real destination.
  const hasAppUrl = !!(app.appUrl && app.appUrl.trim());
  const magicLinkDisabled = saving || !hasAppUrl;

  async function save() {
    setSaving(true);
    try {
      const res = await axios.put<App>(`${cardURL}/auth-method-config`, { primaryAuthMethod });
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Stack spacing={3.5} sx={{ maxWidth: 680 }}>
      <Section
        overline={t("apps.sectionOverline.authentication", { defaultValue: "Authentication" })}
        title={t("apps.primaryAuthTitle", { defaultValue: "Email sign-in" })}
        desc={t("apps.primaryAuthDesc", { defaultValue: "Pick how the email field behaves on the sign-in screen. Password, sign-in code, and magic link are mutually exclusive - only one form can be shown. Choose “No email form” if this app is OAuth-only." })}
      >
        <RadioGroup
          value={primaryAuthMethod}
          onChange={(e) => setPrimaryAuthMethod(e.target.value as PrimaryAuthMethod)}
        >
          <FormControlLabel
            value="password"
            control={<Radio disabled={saving} />}
            label={
              <Stack>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.primaryAuth.password", { defaultValue: "Email + password" })}</Typography>
                <Typography variant="caption" color="text.secondary">{t("apps.primaryAuth.passwordDesc", { defaultValue: "Standard password sign-in. Users without a password set fall back to a one-time code over email." })}</Typography>
              </Stack>
            }
            sx={{ alignItems: "flex-start", ml: 0 }}
          />
          <FormControlLabel
            value="code"
            control={<Radio disabled={saving} />}
            label={
              <Stack>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.primaryAuth.code", { defaultValue: "Email + sign-in code" })}</Typography>
                <Typography variant="caption" color="text.secondary">{t("apps.primaryAuth.codeDesc", { defaultValue: "Passwordless. Users enter their email, receive a 6-digit code, and sign in. Uses the default mailer unless custom SMTP is configured." })}</Typography>
              </Stack>
            }
            sx={{ alignItems: "flex-start", ml: 0 }}
          />
          <FormControlLabel
            value="magicLink"
            control={<Radio disabled={magicLinkDisabled} />}
            label={
              <Stack>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.primaryAuth.magicLink", { defaultValue: "Email magic link" })}</Typography>
                <Typography variant="caption" color="text.secondary">{t("apps.primaryAuth.magicLinkDesc", { defaultValue: "Passwordless. Users enter their email and receive a one-click sign-in link. Requires an App URL (the link points back to your app)." })}</Typography>
                {!hasAppUrl && (
                  <Typography variant="caption" color="warning.main">
                    {t("apps.primaryAuth.magicLinkNeedsAppUrl", { defaultValue: "Set an App URL on the app's main page to enable this option." })}
                  </Typography>
                )}
              </Stack>
            }
            sx={{ alignItems: "flex-start", ml: 0 }}
          />
          <FormControlLabel
            value="none"
            control={<Radio disabled={saving} />}
            label={
              <Stack>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.primaryAuth.none", { defaultValue: "No email form (OAuth-only)" })}</Typography>
                <Typography variant="caption" color="text.secondary">{t("apps.primaryAuth.noneDesc", { defaultValue: "Hide the email field entirely. At least one OAuth provider must be enabled." })}</Typography>
              </Stack>
            }
            sx={{ alignItems: "flex-start", ml: 0 }}
          />
        </RadioGroup>
      </Section>
      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Stack>
  );
}

// =====================================================================
// OAuth providers - single list view that swaps in the per-provider
// card when a row is expanded. Replaces the four sibling tabs (Google,
// Apple, Microsoft, GitHub) so the tab strip doesn't keep growing as
// more providers are added.
//
// The enable toggle still lives inside each provider's expanded panel
// (where the existing "Enable X Sign-In" switch is) - the collapsed
// row only shows a read-only status chip so there's exactly one place
// to flip a provider on/off.
// =====================================================================

type OAuthProviderRow = {
  key: "google" | "apple" | "microsoft" | "github";
  label: string;
  enabled: boolean;
  render: () => React.ReactNode;
};

// ProviderIcon renders the brand mark next to each provider name.
// Inline SVGs (no extra dep) at 18×18 - Google + Microsoft keep brand
// colours because the multicolor marks are how operators recognise
// them at a glance; Apple + GitHub stay monochrome to follow Apple's
// own guidelines and the GitHub octocat tradition.
function ProviderIcon({ name }: { name: OAuthProviderRow["key"] }) {
  switch (name) {
    case "google":
      return (
        <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
          <path fill="#FFC107" d="M43.6 20.5H42V20.4H24v7.2h11.3c-1.5 4.2-5.5 7.2-10.3 7.2-6 0-10.8-4.8-10.8-10.8S18.9 13.2 24.9 13.2c2.7 0 5.2 1 7.1 2.7l5.1-5.1C33.9 7.6 29.7 6 25 6 14.5 6 6 14.5 6 25s8.5 19 19 19c10.5 0 19-8.5 19-19 0-1.3-.1-2.5-.4-4.5z"/>
          <path fill="#FF3D00" d="M8.3 14.7l5.9 4.3c1.6-4 5.4-6.8 9.9-6.8 2.7 0 5.2 1 7.1 2.7l5.1-5.1C33.9 7.6 29.7 6 25 6 17.7 6 11.5 10 8.3 14.7z"/>
          <path fill="#4CAF50" d="M25 44c4.6 0 8.7-1.5 11.9-4.1l-5.5-4.6c-1.8 1.2-4 1.9-6.4 1.9-4.8 0-8.8-3-10.3-7.2l-5.9 4.5C12.2 39.6 18.2 44 25 44z"/>
          <path fill="#1976D2" d="M43.6 20.5H42V20.4H24v7.2h11.3c-.7 2-2.1 3.8-3.9 5l5.5 4.6c-.4.4 6.1-4.5 6.1-12.7 0-1.3-.1-2.5-.4-4.5z"/>
        </svg>
      );
    case "apple":
      return (
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="currentColor">
          <path d="M17.05 12.04c-.03-2.97 2.42-4.39 2.53-4.46-1.38-2.02-3.53-2.3-4.3-2.33-1.83-.19-3.57 1.08-4.5 1.08-.94 0-2.37-1.05-3.9-1.02-2 .03-3.86 1.17-4.89 2.96-2.09 3.62-.53 8.96 1.5 11.9 1 1.43 2.18 3.04 3.72 2.98 1.5-.06 2.07-.96 3.88-.96 1.8 0 2.32.96 3.9.93 1.62-.03 2.63-1.45 3.6-2.89 1.14-1.66 1.6-3.27 1.62-3.35-.03-.02-3.13-1.2-3.16-4.77zM14.34 3.44c.83-1 1.39-2.4 1.24-3.79-1.2.05-2.65.79-3.5 1.79-.77.89-1.44 2.31-1.26 3.67 1.34.1 2.7-.68 3.52-1.67z"/>
        </svg>
      );
    case "microsoft":
      return (
        <svg width="18" height="18" viewBox="0 0 23 23" aria-hidden="true">
          <rect x="1"  y="1"  width="10" height="10" fill="#F25022"/>
          <rect x="12" y="1"  width="10" height="10" fill="#7FBA00"/>
          <rect x="1"  y="12" width="10" height="10" fill="#00A4EF"/>
          <rect x="12" y="12" width="10" height="10" fill="#FFB900"/>
        </svg>
      );
    case "github":
      return (
        <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="currentColor">
          <path d="M12 .5C5.4.5 0 5.9 0 12.5c0 5.3 3.4 9.8 8.2 11.4.6.1.8-.3.8-.6v-2.1c-3.3.7-4-1.6-4-1.6-.6-1.4-1.4-1.8-1.4-1.8-1.1-.8.1-.8.1-.8 1.2.1 1.9 1.3 1.9 1.3 1.1 1.9 2.9 1.4 3.6 1 .1-.8.4-1.4.8-1.7-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.3-3.3-.1-.3-.6-1.6.1-3.3 0 0 1-.3 3.3 1.3 1-.3 2-.4 3-.4s2 .1 3 .4c2.3-1.6 3.3-1.3 3.3-1.3.7 1.7.2 3 .1 3.3.8.9 1.3 2 1.3 3.3 0 4.7-2.8 5.7-5.5 6 .4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6 4.8-1.6 8.2-6.1 8.2-11.4C24 5.9 18.6.5 12 .5z"/>
        </svg>
      );
  }
}

function OAuthProvidersList({ app, cardURL, onSaved, onSuccess, onError }: CardProps) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = React.useState<OAuthProviderRow["key"] | null>(null);

  const providers: OAuthProviderRow[] = [
    {
      key: "google",
      label: "Google",
      enabled: app.authMethodGoogle,
      render: () => (
        <GoogleCard app={app} cardURL={cardURL} onSaved={onSaved} onSuccess={onSuccess} onError={onError} />
      ),
    },
    {
      key: "apple",
      label: "Apple",
      enabled: !!app.authMethodApple,
      render: () => (
        <AppleCard app={app} cardURL={cardURL} onSaved={onSaved} onSuccess={onSuccess} onError={onError} />
      ),
    },
    {
      key: "microsoft",
      label: "Microsoft",
      enabled: !!app.authMethodMicrosoft,
      render: () => (
        <MicrosoftCard app={app} cardURL={cardURL} onSaved={onSaved} onSuccess={onSuccess} onError={onError} />
      ),
    },
    {
      key: "github",
      label: "GitHub",
      enabled: !!app.authMethodGithub,
      render: () => (
        <GithubCard app={app} cardURL={cardURL} onSaved={onSaved} onSuccess={onSuccess} onError={onError} />
      ),
    },
  ];

  return (
    <Stack spacing={1.25}>
      <Typography variant="body2" color="text.secondary">
        {t("apps.oauth.intro", {
          defaultValue:
            "Add social sign-in providers. Click a provider to configure its credentials; each provider's own switch enables or disables it.",
        })}
      </Typography>

      {/* Flex+gap instead of Stack spacing - MUI's Accordion ships
          with margin overrides that win over Stack's adjacent-sibling
          margin rule and collapse the gap to zero. flex gap doesn't
          rely on child margins so it's immune to that. */}
      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
        {providers.map((p) => {
          const open = expanded === p.key;
          return (
            <Accordion
              key={p.key}
              expanded={open}
              onChange={() => setExpanded(open ? null : p.key)}
              disableGutters
              square={false}
              elevation={0}
              sx={{
                border: "1px solid",
                borderColor: "divider",
                borderRadius: 2,
                overflow: "hidden",
                "&:before": { display: "none" },
                // MUI bumps top margin on Mui-expanded by default; we
                // already control spacing via the parent flex gap, so
                // pin to 0 in both states.
                "&.Mui-expanded": { m: 0 },
              }}
            >
              <AccordionSummary
                expandIcon={<ChevronDown size={16} strokeWidth={1.75} />}
                sx={{
                  px: 2,
                  // MUI defaults bump minHeight + content margins on
                  // Mui-expanded, which makes the row visibly grow when
                  // you open it. Pin both states to the same values so
                  // the row stays a stable height in both modes.
                  minHeight: 48,
                  "&.Mui-expanded": { minHeight: 48 },
                  "& .MuiAccordionSummary-content": {
                    my: 0.75,
                    alignItems: "center",
                    gap: 1.5,
                  },
                  "& .MuiAccordionSummary-content.Mui-expanded": { my: 0.75 },
                }}
              >
                <Box
                  sx={{
                    width: 20,
                    height: 20,
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    flexShrink: 0,
                    color: "text.primary",
                  }}
                >
                  <ProviderIcon name={p.key} />
                </Box>
                <Typography sx={{ fontSize: 14.5, fontWeight: 500, flexGrow: 1 }}>{p.label}</Typography>
                <Chip
                  size="small"
                  label={p.enabled ? t("common.enabled", { defaultValue: "Enabled" }) : t("common.disabled", { defaultValue: "Disabled" })}
                  variant="outlined"
                  sx={{
                    height: 22,
                    fontSize: 11,
                    fontFamily: "var(--font-mono)",
                    letterSpacing: "0.08em",
                    textTransform: "uppercase",
                    fontWeight: 500,
                    ...(p.enabled && {
                      borderColor: "success.main",
                      color: "success.main",
                    }),
                  }}
                />
              </AccordionSummary>
              <AccordionDetails sx={{ px: 2, pt: 2, pb: 2.5, borderTop: "1px solid", borderColor: "divider" }}>
                {open && p.render()}
              </AccordionDetails>
            </Accordion>
          );
        })}
      </Box>
    </Stack>
  );
}

// =====================================================================
// Google - toggle + credentials together. Toggle gated on client_id.
// =====================================================================

function GoogleCard({ app, cardURL, onSaved, onSuccess, onError }: CardProps) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const [enabled, setEnabled] = React.useState(app.authMethodGoogle);
  const [clientId, setClientId] = React.useState(app.googleOAuthClientId || "");
  const [clientSecret, setClientSecret] = React.useState("");
  const [clearSecret, setClearSecret] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  const resetFromApp = React.useCallback(() => {
    setEnabled(app.authMethodGoogle);
    setClientId(app.googleOAuthClientId || "");
    setClientSecret("");
    setClearSecret(false);
  }, [app]);

  React.useEffect(() => { resetFromApp(); }, [resetFromApp]);

  const dirty =
    enabled !== app.authMethodGoogle ||
    clientId !== (app.googleOAuthClientId || "") ||
    clientSecret.trim().length > 0 ||
    clearSecret;

  const secretAvailable = clientSecret.trim().length > 0 || (!!app.hasGoogleClientSecret && !clearSecret);
  const configComplete = clientId.trim().length > 0 && secretAvailable;

  async function save() {
    if (enabled && clientId.trim().length === 0) {
      onError(new Error(t("apps.googleClientIdRequired", { defaultValue: "Enter a Client ID before enabling Google sign-in." })));
      return;
    }
    if (enabled && !secretAvailable) {
      onError(new Error(t("apps.googleClientSecretRequired", { defaultValue: "Enter a Client Secret before enabling Google sign-in." })));
      return;
    }
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        authMethodGoogle: enabled,
        googleOAuthClientId: clientId.trim(),
      };
      if (clientSecret.trim()) body.googleOAuthClientSecret = clientSecret.trim();
      else if (clearSecret) body.googleOAuthClientSecret = "";
      const res = await axios.put<App>(`${cardURL}/google-config`, body);
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  async function copy(text: string, label: string) {
    try { await navigator.clipboard.writeText(text); enqueueSnackbar(t("apps.copied", { label }), { variant: "success" }); }
    catch { enqueueSnackbar(t("apps.copyFailed"), { variant: "error" }); }
  }

  return (
    <Stack spacing={3.5} sx={{ maxWidth: 680 }}>
      <Section
        overline={t("apps.sectionOverline.oauthProvider", { defaultValue: "OAuth provider" })}
        title={t("apps.googleConfigTitle", { defaultValue: "Google Sign-In" })}
        desc={t("apps.googleConfigDesc", { defaultValue: "Credentials from Google Cloud Console. Both Client ID and Client Secret are required - sign-in uses the OAuth Authorization Code Flow, which does a server-to-server token exchange." })}
      >
        <FormControlLabel
          control={
            <Switch
              checked={enabled}
              onChange={(e) => {
                const next = e.target.checked;
                if (next && clientId.trim().length === 0) {
                  enqueueSnackbar(t("apps.googleClientIdRequired", { defaultValue: "Enter a Client ID before enabling Google sign-in." }), { variant: "warning" });
                  return;
                }
                if (next && !secretAvailable) {
                  enqueueSnackbar(t("apps.googleClientSecretRequired", { defaultValue: "Enter a Client Secret before enabling Google sign-in." }), { variant: "warning" });
                  return;
                }
                setEnabled(next);
              }}
              disabled={saving}
            />
          }
          label={
            <Stack spacing={0}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.dialog.authMethodGoogle", { defaultValue: "Enable Google Sign-In" })}</Typography>
              {!configComplete && (
                <Typography variant="caption" color="text.secondary">{t("apps.googleConfigRequired", { defaultValue: "Configure the Client ID and Client Secret below first." })}</Typography>
              )}
            </Stack>
          }
          sx={{ ml: 0 }}
        />

        <TextField
          size="small"
          fullWidth
          label={t("apps.dialog.googleClientIdLabel", { defaultValue: "Client ID" })}
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          disabled={saving}
          placeholder="123456789.apps.googleusercontent.com"
          helperText={t("apps.dialog.googleClientIdHelp", { defaultValue: "From Google Cloud Console → Credentials → OAuth 2.0 Client ID" })}
        />
        <TextField
          size="small"
          fullWidth
          type="password"
          label={
            <Box component="span" sx={{ display: "inline-flex", alignItems: "center", gap: 1 }}>
              <span>{t("apps.dialog.googleClientSecretLabel", { defaultValue: "Client Secret" })}</span>
              {app.hasGoogleClientSecret && !clearSecret && (
                <StatusChip size="xs" label={t("apps.dialog.secretSet", { defaultValue: "Configured" })} severity="success" />
              )}
              {clearSecret && (
                <StatusChip size="xs" label="Will be cleared on save" severity="warning" />
              )}
            </Box>
          }
          value={clientSecret}
          onChange={(e) => { setClientSecret(e.target.value); setClearSecret(false); }}
          disabled={saving || clearSecret}
          placeholder={app.hasGoogleClientSecret && !clearSecret ? "Leave blank to keep current" : "Required - paste from Google Cloud Console"}
          helperText={
            <Box component="span" sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span>{t("apps.dialog.googleClientSecretHelp", { defaultValue: "Required. ManyRows exchanges the OAuth code server-to-server with this secret." })}</span>
              {app.hasGoogleClientSecret && !clearSecret && (
                <Button size="small" color="error" onClick={() => { setClearSecret(true); setClientSecret(""); }} sx={{ textTransform: "none", fontSize: 11, minWidth: 0, p: 0, ml: 1, whiteSpace: "nowrap" }}>Clear secret</Button>
              )}
              {clearSecret && (
                <Button size="small" onClick={() => setClearSecret(false)} sx={{ textTransform: "none", fontSize: 11, minWidth: 0, p: 0, ml: 1, whiteSpace: "nowrap" }}>Undo</Button>
              )}
            </Box>
          }
        />
        {app.googleOAuthRedirectUri && (
          <CopyableUri
            label={t("apps.dialog.googleRedirectUriLabel", { defaultValue: "Authorized Redirect URI" })}
            uri={app.googleOAuthRedirectUri}
            onCopy={() => copy(app.googleOAuthRedirectUri!, "Redirect URI")}
            help={t("apps.dialog.googleRedirectUriHelp", { defaultValue: "Add this to Google Cloud Console → Credentials → Authorized redirect URIs" })}
            copyTitle={t("apps.copyRedirectUri", { defaultValue: "Copy redirect URI" })}
          />
        )}
      </Section>
      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Stack>
  );
}

// =====================================================================
// Apple - toggle + credentials together. Toggle gated on full cred set.
// =====================================================================

function AppleCard({ app, cardURL, onSaved, onSuccess, onError }: CardProps) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const [enabled, setEnabled] = React.useState(!!app.authMethodApple);
  const [servicesId, setServicesId] = React.useState(app.appleServicesId || "");
  const [teamId, setTeamId] = React.useState(app.appleTeamId || "");
  const [keyId, setKeyId] = React.useState(app.appleKeyId || "");
  const [privateKey, setPrivateKey] = React.useState("");
  const [clearKey, setClearKey] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  const resetFromApp = React.useCallback(() => {
    setEnabled(!!app.authMethodApple);
    setServicesId(app.appleServicesId || "");
    setTeamId(app.appleTeamId || "");
    setKeyId(app.appleKeyId || "");
    setPrivateKey("");
    setClearKey(false);
  }, [app]);

  React.useEffect(() => { resetFromApp(); }, [resetFromApp]);

  const dirty =
    enabled !== !!app.authMethodApple ||
    servicesId !== (app.appleServicesId || "") ||
    teamId !== (app.appleTeamId || "") ||
    keyId !== (app.appleKeyId || "") ||
    privateKey.trim().length > 0 ||
    clearKey;

  // post-save key state: existing key still there (unless clearing) OR user is typing a new one.
  const willHaveKey = !clearKey && (!!app.hasApplePrivateKey || privateKey.trim().length > 0);
  const configComplete =
    servicesId.trim().length > 0 &&
    teamId.trim().length > 0 &&
    keyId.trim().length > 0 &&
    willHaveKey;

  async function save() {
    if (enabled && !configComplete) {
      onError(new Error(t("apps.appleConfigIncomplete", { defaultValue: "Fill all Apple credential fields before enabling." })));
      return;
    }
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        authMethodApple: enabled,
        appleServicesId: servicesId.trim(),
        appleTeamId: teamId.trim(),
        appleKeyId: keyId.trim(),
      };
      if (privateKey.trim()) body.applePrivateKey = privateKey;
      else if (clearKey) body.applePrivateKey = "";
      const res = await axios.put<App>(`${cardURL}/apple-config`, body);
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  async function copy(text: string, label: string) {
    try { await navigator.clipboard.writeText(text); enqueueSnackbar(t("apps.copied", { label }), { variant: "success" }); }
    catch { enqueueSnackbar(t("apps.copyFailed"), { variant: "error" }); }
  }

  return (
    <Stack spacing={3.5} sx={{ maxWidth: 680 }}>
      <Section
        overline={t("apps.sectionOverline.oauthProvider", { defaultValue: "OAuth provider" })}
        title={t("apps.appleConfigTitle", { defaultValue: "Apple Sign-In" })}
        desc={t("apps.appleConfigDesc", { defaultValue: "Apple Developer credentials. Services ID is the OAuth client_id; the .p8 private key is used to mint short-lived ES256 client-secret JWTs at sign-in time." })}
      >
        <FormControlLabel
          control={
            <Switch
              checked={enabled}
              onChange={(e) => {
                const next = e.target.checked;
                if (next && !configComplete) {
                  enqueueSnackbar(t("apps.appleConfigIncomplete", { defaultValue: "Fill all Apple credential fields before enabling." }), { variant: "warning" });
                  return;
                }
                setEnabled(next);
              }}
              disabled={saving}
            />
          }
          label={
            <Stack spacing={0}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.dialog.authMethodApple", { defaultValue: "Enable Apple Sign-In" })}</Typography>
              {!configComplete && (
                <Typography variant="caption" color="text.secondary">{t("apps.appleConfigRequired", { defaultValue: "Fill all four credential fields below first." })}</Typography>
              )}
            </Stack>
          }
          sx={{ ml: 0 }}
        />

        <TextField
          size="small" fullWidth
          label={t("apps.dialog.appleServicesIdLabel", { defaultValue: "Services ID" })}
          value={servicesId}
          onChange={(e) => setServicesId(e.target.value)}
          disabled={saving}
          placeholder="com.example.signin"
          helperText={t("apps.dialog.appleServicesIdHelp", { defaultValue: "From Apple Developer → Identifiers → Services IDs" })}
        />
        <TextField
          size="small" fullWidth
          label={t("apps.dialog.appleTeamIdLabel", { defaultValue: "Team ID" })}
          value={teamId}
          onChange={(e) => setTeamId(e.target.value)}
          disabled={saving}
          placeholder="ABCDE12345"
          helperText={t("apps.dialog.appleTeamIdHelp", { defaultValue: "10-character Team ID from Apple Developer membership page" })}
        />
        <TextField
          size="small" fullWidth
          label={t("apps.dialog.appleKeyIdLabel", { defaultValue: "Key ID" })}
          value={keyId}
          onChange={(e) => setKeyId(e.target.value)}
          disabled={saving}
          placeholder="ABC123XYZ4"
          helperText={t("apps.dialog.appleKeyIdHelp", { defaultValue: "10-character Key ID for the Sign in with Apple key" })}
        />
        <TextField
          size="small" fullWidth multiline minRows={4}
          label={
            <Box component="span" sx={{ display: "inline-flex", alignItems: "center", gap: 1 }}>
              <span>{t("apps.dialog.applePrivateKeyLabel", { defaultValue: "Private Key (.p8)" })}</span>
              {app.hasApplePrivateKey && !clearKey && (
                <StatusChip size="xs" label={t("apps.dialog.secretSet", { defaultValue: "Configured" })} severity="success" />
              )}
              {clearKey && (
                <StatusChip size="xs" label="Will be cleared on save" severity="warning" />
              )}
            </Box>
          }
          value={privateKey}
          onChange={(e) => { setPrivateKey(e.target.value); setClearKey(false); }}
          disabled={saving || clearKey}
          placeholder={app.hasApplePrivateKey && !clearKey ? "Leave blank to keep current" : "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"}
          helperText={
            <Box component="span" sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span>{t("apps.dialog.applePrivateKeyHelp", { defaultValue: "Paste the contents of the .p8 file from Apple Developer. Encrypted at rest." })}</span>
              {app.hasApplePrivateKey && !clearKey && (
                <Button size="small" color="error" onClick={() => { setClearKey(true); setPrivateKey(""); }} sx={{ textTransform: "none", fontSize: 11, minWidth: 0, p: 0, ml: 1, whiteSpace: "nowrap" }}>Clear key</Button>
              )}
              {clearKey && (
                <Button size="small" onClick={() => setClearKey(false)} sx={{ textTransform: "none", fontSize: 11, minWidth: 0, p: 0, ml: 1, whiteSpace: "nowrap" }}>Undo</Button>
              )}
            </Box>
          }
        />
        {app.appleOAuthRedirectUri && (
          <CopyableUri
            label={t("apps.dialog.appleRedirectUriLabel", { defaultValue: "Return URL (Apple)" })}
            uri={app.appleOAuthRedirectUri}
            onCopy={() => copy(app.appleOAuthRedirectUri!, "Return URL")}
            help={t("apps.dialog.appleRedirectUriHelp", { defaultValue: "Add this to Apple Developer → Services ID → Sign in with Apple → Return URLs" })}
            copyTitle={t("apps.copyRedirectUri", { defaultValue: "Copy redirect URI" })}
          />
        )}
      </Section>
      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Stack>
  );
}

// =====================================================================
// Microsoft - toggle + credentials + tenant scope. Toggle gated on
// having both Client ID and Client Secret.
// =====================================================================

const MS_TENANT_PRESETS = ["common", "organizations", "consumers"] as const;

function MicrosoftCard({ app, cardURL, onSaved, onSuccess, onError }: CardProps) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const initialTenant = app.microsoftTenant || "common";
  const isPreset = (MS_TENANT_PRESETS as readonly string[]).includes(initialTenant);

  const [enabled, setEnabled] = React.useState(!!app.authMethodMicrosoft);
  const [clientId, setClientId] = React.useState(app.microsoftClientId || "");
  const [clientSecret, setClientSecret] = React.useState("");
  const [clearSecret, setClearSecret] = React.useState(false);
  const [tenantMode, setTenantMode] = React.useState<string>(isPreset ? initialTenant : "specific");
  const [specificTenant, setSpecificTenant] = React.useState(isPreset ? "" : initialTenant);
  const [saving, setSaving] = React.useState(false);

  const resetFromApp = React.useCallback(() => {
    const t0 = app.microsoftTenant || "common";
    const preset = (MS_TENANT_PRESETS as readonly string[]).includes(t0);
    setEnabled(!!app.authMethodMicrosoft);
    setClientId(app.microsoftClientId || "");
    setClientSecret("");
    setClearSecret(false);
    setTenantMode(preset ? t0 : "specific");
    setSpecificTenant(preset ? "" : t0);
  }, [app]);

  React.useEffect(() => { resetFromApp(); }, [resetFromApp]);

  const savedTenant = app.microsoftTenant || "common";
  const savedTenantMode = (MS_TENANT_PRESETS as readonly string[]).includes(savedTenant) ? savedTenant : "specific";
  const savedSpecificTenant = (MS_TENANT_PRESETS as readonly string[]).includes(savedTenant) ? "" : savedTenant;

  const dirty =
    enabled !== !!app.authMethodMicrosoft ||
    clientId !== (app.microsoftClientId || "") ||
    clientSecret.trim().length > 0 ||
    clearSecret ||
    tenantMode !== savedTenantMode ||
    specificTenant !== savedSpecificTenant;

  const willHaveSecret = !clearSecret && (!!app.hasMicrosoftClientSecret || clientSecret.trim().length > 0);
  const tenantValue =
    tenantMode === "specific"
      ? specificTenant.trim()
      : tenantMode;
  const tenantValid =
    tenantMode !== "specific" ||
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(tenantValue);
  const configComplete = clientId.trim().length > 0 && willHaveSecret && tenantValid;
  const isMultiTenant = tenantMode !== "specific";

  async function save() {
    if (!tenantValid) {
      onError(new Error(t("apps.microsoftTenantInvalid", { defaultValue: "Tenant ID must be a UUID, or pick one of the preset scopes." })));
      return;
    }
    if (enabled && !configComplete) {
      onError(new Error(t("apps.microsoftConfigIncomplete", { defaultValue: "Configure Client ID and Client Secret before enabling Microsoft sign-in." })));
      return;
    }
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        authMethodMicrosoft: enabled,
        microsoftClientId: clientId.trim(),
        microsoftTenant: tenantValue,
      };
      if (clientSecret.trim()) body.microsoftClientSecret = clientSecret.trim();
      else if (clearSecret) body.microsoftClientSecret = "";
      const res = await axios.put<App>(`${cardURL}/microsoft-config`, body);
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  async function copy(text: string, label: string) {
    try { await navigator.clipboard.writeText(text); enqueueSnackbar(t("apps.copied", { label }), { variant: "success" }); }
    catch { enqueueSnackbar(t("apps.copyFailed"), { variant: "error" }); }
  }

  return (
    <Stack spacing={3.5} sx={{ maxWidth: 680 }}>
      <Section
        overline={t("apps.sectionOverline.oauthProvider", { defaultValue: "OAuth provider" })}
        title={t("apps.microsoftConfigTitle", { defaultValue: "Microsoft Sign-In" })}
        desc={t("apps.microsoftConfigDesc", { defaultValue: "Application credentials from Entra ID (Azure AD). The tenant scope decides which kinds of Microsoft accounts can sign in." })}
      >
        {/* Multi-tenant scopes require xms_edov, which Microsoft does
            NOT include in tokens by default. This isn't surfaced in
            Entra's normal token-config UI - admins have to add it via
            Graph API or manifest edit. Without this banner, customers
            would discover the requirement only after their users hit
            the (deliberately generic) sign-in error. */}
        {isMultiTenant && (
          <Alert severity="warning" sx={{ fontSize: 13 }}>
            <Typography variant="body2" sx={{ fontWeight: 500, mb: 0.5 }}>
              {t("apps.microsoftXmsEdovTitle", { defaultValue: "Required: enable the xms_edov optional claim in Entra" })}
            </Typography>
            <Typography variant="caption" color="text.secondary" component="div">
              {t("apps.microsoftXmsEdovBody", {
                defaultValue:
                  "When the tenant scope is Common, Organizations, or Consumers, ManyRows requires the xms_edov claim (Email Domain Owner Verified) to defend against the multi-tenant email-spoofing pattern. xms_edov isn't emitted by default and isn't visible in Entra's standard Token Configuration UI - your tenant admin must add it via Graph API or by editing the app manifest. Without it, every Microsoft sign-in to this app will fail. Pick \"Single tenant\" instead if you want to skip this requirement (the customer trusts only their own tenant).",
              })}
            </Typography>
          </Alert>
        )}

        <FormControlLabel
          control={
            <Switch
              checked={enabled}
              onChange={(e) => {
                const next = e.target.checked;
                if (next && !configComplete) {
                  enqueueSnackbar(t("apps.microsoftConfigIncomplete", { defaultValue: "Configure Client ID and Client Secret before enabling Microsoft sign-in." }), { variant: "warning" });
                  return;
                }
                setEnabled(next);
              }}
              disabled={saving}
            />
          }
          label={
            <Stack spacing={0}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.dialog.authMethodMicrosoft", { defaultValue: "Enable Microsoft Sign-In" })}</Typography>
              {!configComplete && (
                <Typography variant="caption" color="text.secondary">{t("apps.microsoftConfigRequired", { defaultValue: "Configure Client ID + Client Secret below first." })}</Typography>
              )}
            </Stack>
          }
          sx={{ ml: 0 }}
        />

        <TextField
          size="small"
          fullWidth
          label={t("apps.dialog.microsoftClientIdLabel", { defaultValue: "Application (Client) ID" })}
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          disabled={saving}
          placeholder="00000000-0000-0000-0000-000000000000"
          helperText={t("apps.dialog.microsoftClientIdHelp", { defaultValue: "From Microsoft Entra → App registrations → Application (client) ID" })}
        />
        <TextField
          size="small"
          fullWidth
          type="password"
          label={
            <Box component="span" sx={{ display: "inline-flex", alignItems: "center", gap: 1 }}>
              <span>{t("apps.dialog.microsoftClientSecretLabel", { defaultValue: "Client Secret (Value)" })}</span>
              {app.hasMicrosoftClientSecret && !clearSecret && (
                <StatusChip size="xs" label={t("apps.dialog.secretSet", { defaultValue: "Configured" })} severity="success" />
              )}
              {clearSecret && (
                <StatusChip size="xs" label="Will be cleared on save" severity="warning" />
              )}
            </Box>
          }
          value={clientSecret}
          onChange={(e) => { setClientSecret(e.target.value); setClearSecret(false); }}
          disabled={saving || clearSecret}
          placeholder={app.hasMicrosoftClientSecret && !clearSecret ? "Leave blank to keep current" : "From Entra → Certificates & secrets → New client secret → Value"}
          helperText={
            <Box component="span" sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span>{t("apps.dialog.microsoftClientSecretHelp", { defaultValue: "Use the Value column from the secret you created in Entra (not the Secret ID). Encrypted at rest." })}</span>
              {app.hasMicrosoftClientSecret && !clearSecret && (
                <Button size="small" color="error" onClick={() => { setClearSecret(true); setClientSecret(""); }} sx={{ textTransform: "none", fontSize: 11, minWidth: 0, p: 0, ml: 1, whiteSpace: "nowrap" }}>Clear secret</Button>
              )}
              {clearSecret && (
                <Button size="small" onClick={() => setClearSecret(false)} sx={{ textTransform: "none", fontSize: 11, minWidth: 0, p: 0, ml: 1, whiteSpace: "nowrap" }}>Undo</Button>
              )}
            </Box>
          }
        />

        <FormControl fullWidth size="small" disabled={saving}>
          <InputLabel id="ms-tenant-label">{t("apps.dialog.microsoftTenantLabel", { defaultValue: "Tenant scope" })}</InputLabel>
          <Select
            labelId="ms-tenant-label"
            label={t("apps.dialog.microsoftTenantLabel", { defaultValue: "Tenant scope" })}
            value={tenantMode}
            onChange={(e) => setTenantMode(String(e.target.value))}
          >
            <MenuItem value="common">{t("apps.dialog.microsoftTenantCommon", { defaultValue: "Common - work/school + personal Microsoft accounts" })}</MenuItem>
            <MenuItem value="organizations">{t("apps.dialog.microsoftTenantOrganizations", { defaultValue: "Organizations - work/school accounts only" })}</MenuItem>
            <MenuItem value="consumers">{t("apps.dialog.microsoftTenantConsumers", { defaultValue: "Consumers - personal Microsoft accounts only" })}</MenuItem>
            <MenuItem value="specific">{t("apps.dialog.microsoftTenantSpecific", { defaultValue: "Single tenant - only one organization" })}</MenuItem>
          </Select>
          <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
            {t("apps.dialog.microsoftTenantHelp", { defaultValue: "Common is the broadest reach. Organizations is the safer SaaS default - blocks personal Outlook accounts. Single tenant restricts sign-in to one specific Entra organization." })}
          </Typography>
        </FormControl>

        {tenantMode === "specific" && (
          <TextField
            size="small"
            fullWidth
            label={t("apps.dialog.microsoftTenantIdLabel", { defaultValue: "Tenant ID (UUID)" })}
            value={specificTenant}
            onChange={(e) => setSpecificTenant(e.target.value)}
            disabled={saving}
            placeholder="00000000-0000-0000-0000-000000000000"
            error={specificTenant.length > 0 && !tenantValid}
            helperText={
              specificTenant.length > 0 && !tenantValid
                ? t("apps.dialog.microsoftTenantIdInvalid", { defaultValue: "Must be a UUID (Directory ID) from your Entra tenant." })
                : t("apps.dialog.microsoftTenantIdHelp", { defaultValue: "From Entra ID Overview → Directory (tenant) ID. Only users in this organization can sign in." })
            }
          />
        )}

        {app.microsoftOAuthRedirectUri && (
          <CopyableUri
            label={t("apps.dialog.microsoftRedirectUriLabel", { defaultValue: "Redirect URI" })}
            uri={app.microsoftOAuthRedirectUri}
            onCopy={() => copy(app.microsoftOAuthRedirectUri!, "Redirect URI")}
            help={t("apps.dialog.microsoftRedirectUriHelp", { defaultValue: "Add this to Entra → App registrations → Authentication → Web → Redirect URIs" })}
            copyTitle={t("apps.copyRedirectUri", { defaultValue: "Copy redirect URI" })}
          />
        )}
      </Section>
      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Stack>
  );
}

// =====================================================================
// GitHub - toggle + OAuth credentials. No tenant scope; the trust
// boundary is GitHub's own /user/emails verified flag.
// =====================================================================

function GithubCard({ app, cardURL, onSaved, onSuccess, onError }: CardProps) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const [enabled, setEnabled] = React.useState(!!app.authMethodGithub);
  const [clientId, setClientId] = React.useState(app.githubClientId || "");
  const [clientSecret, setClientSecret] = React.useState("");
  const [clearSecret, setClearSecret] = React.useState(false);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    setEnabled(!!app.authMethodGithub);
    setClientId(app.githubClientId || "");
    setClientSecret("");
    setClearSecret(false);
  }, [app]);

  const resetFromApp = React.useCallback(() => {
    setEnabled(!!app.authMethodGithub);
    setClientId(app.githubClientId || "");
    setClientSecret("");
    setClearSecret(false);
  }, [app]);

  const dirty =
    enabled !== !!app.authMethodGithub ||
    clientId !== (app.githubClientId || "") ||
    clientSecret.trim().length > 0 ||
    clearSecret;

  const willHaveSecret = !clearSecret && (!!app.hasGithubClientSecret || clientSecret.trim().length > 0);
  const configComplete = clientId.trim().length > 0 && willHaveSecret;

  async function save() {
    if (enabled && !configComplete) {
      onError(new Error(t("apps.githubConfigIncomplete", { defaultValue: "Configure both Client ID and Client Secret before enabling GitHub sign-in." })));
      return;
    }
    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        authMethodGithub: enabled,
        githubClientId: clientId.trim(),
      };
      if (clientSecret.trim()) body.githubClientSecret = clientSecret.trim();
      else if (clearSecret) body.githubClientSecret = "";
      const res = await axios.put<App>(`${cardURL}/github-config`, body);
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  async function copy(text: string, label: string) {
    try { await navigator.clipboard.writeText(text); enqueueSnackbar(t("apps.copied", { label }), { variant: "success" }); }
    catch { enqueueSnackbar(t("apps.copyFailed"), { variant: "error" }); }
  }

  return (
    <Stack spacing={3.5} sx={{ maxWidth: 680 }}>
      <Section
        overline={t("apps.sectionOverline.oauthProvider", { defaultValue: "OAuth provider" })}
        title={t("apps.githubConfigTitle", { defaultValue: "GitHub Sign-In" })}
        desc={t("apps.githubConfigDesc", { defaultValue: "OAuth App credentials from GitHub Developer Settings. Users sign in with GitHub and we use their primary verified email as the account identifier." })}
      >
        <FormControlLabel
          control={
            <Switch
              checked={enabled}
              onChange={(e) => {
                const next = e.target.checked;
                if (next && !configComplete) {
                  enqueueSnackbar(t("apps.githubConfigIncomplete", { defaultValue: "Configure both Client ID and Client Secret before enabling GitHub sign-in." }), { variant: "warning" });
                  return;
                }
                setEnabled(next);
              }}
              disabled={saving}
            />
          }
          label={
            <Stack spacing={0}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>{t("apps.dialog.authMethodGithub", { defaultValue: "Enable GitHub Sign-In" })}</Typography>
              {!configComplete && (
                <Typography variant="caption" color="text.secondary">{t("apps.githubConfigRequired", { defaultValue: "Configure Client ID + Client Secret below first." })}</Typography>
              )}
            </Stack>
          }
          sx={{ ml: 0 }}
        />

        <TextField
          size="small"
          fullWidth
          label={t("apps.dialog.githubClientIdLabel", { defaultValue: "Client ID" })}
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          disabled={saving}
          placeholder="Iv1.abc123def456"
          helperText={t("apps.dialog.githubClientIdHelp", { defaultValue: "From GitHub → Settings → Developer settings → OAuth Apps → Client ID" })}
        />
        <TextField
          size="small"
          fullWidth
          type="password"
          label={
            <Box component="span" sx={{ display: "inline-flex", alignItems: "center", gap: 1 }}>
              <span>{t("apps.dialog.githubClientSecretLabel", { defaultValue: "Client Secret" })}</span>
              {app.hasGithubClientSecret && !clearSecret && (
                <StatusChip size="xs" label={t("apps.dialog.secretSet", { defaultValue: "Configured" })} severity="success" />
              )}
              {clearSecret && (
                <StatusChip size="xs" label="Will be cleared on save" severity="warning" />
              )}
            </Box>
          }
          value={clientSecret}
          onChange={(e) => { setClientSecret(e.target.value); setClearSecret(false); }}
          disabled={saving || clearSecret}
          placeholder={app.hasGithubClientSecret && !clearSecret ? "Leave blank to keep current" : "Generate a new secret in your OAuth App settings"}
          helperText={
            <Box component="span" sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span>{t("apps.dialog.githubClientSecretHelp", { defaultValue: "Encrypted at rest. GitHub only shows the secret once at generation time - copy it from the OAuth App settings page right after creating it." })}</span>
              {app.hasGithubClientSecret && !clearSecret && (
                <Button size="small" color="error" onClick={() => { setClearSecret(true); setClientSecret(""); }} sx={{ textTransform: "none", fontSize: 11, minWidth: 0, p: 0, ml: 1, whiteSpace: "nowrap" }}>Clear secret</Button>
              )}
              {clearSecret && (
                <Button size="small" onClick={() => setClearSecret(false)} sx={{ textTransform: "none", fontSize: 11, minWidth: 0, p: 0, ml: 1, whiteSpace: "nowrap" }}>Undo</Button>
              )}
            </Box>
          }
        />
        {app.githubOAuthRedirectUri && (
          <CopyableUri
            label={t("apps.dialog.githubRedirectUriLabel", { defaultValue: "Authorization callback URL" })}
            uri={app.githubOAuthRedirectUri}
            onCopy={() => copy(app.githubOAuthRedirectUri!, "Callback URL")}
            help={t("apps.dialog.githubRedirectUriHelp", { defaultValue: "Paste this into the OAuth App's \"Authorization callback URL\" field on GitHub." })}
            copyTitle={t("apps.copyRedirectUri", { defaultValue: "Copy redirect URI" })}
          />
        )}
      </Section>
      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Stack>
  );
}

// =====================================================================
// Passkeys (RPID configuration). Uses its own pre-existing endpoint.
// =====================================================================

function PasskeysCard(props: { appsBaseURL: string; appId: string }) {
  const { appsBaseURL, appId } = props;
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const [rpid, setRpid] = React.useState("");
  const [originalRpid, setOriginalRpid] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    let alive = true;
    axios.get<{ rpid: string | null }>(`${appsBaseURL}/${appId}/webauthn-rpid`)
      .then((res) => {
        if (!alive) return;
        const next = res.data?.rpid ?? null;
        setRpid(next ?? "");
        setOriginalRpid(next);
      })
      .catch(() => { /* not configured yet */ });
    return () => { alive = false; };
  }, [appsBaseURL, appId]);

  async function save() {
    setSaving(true);
    try {
      const trimmed = rpid.trim();
      const body = { rpid: trimmed === "" ? null : trimmed };
      const res = await axios.put<{ rpid: string | null }>(`${appsBaseURL}/${appId}/webauthn-rpid`, body);
      const saved = res.data?.rpid ?? null;
      setRpid(saved ?? "");
      setOriginalRpid(saved);
      enqueueSnackbar(t("apps.passkeyRPIDSaved", { defaultValue: "Passkey RPID saved" }), { variant: "success" });
    } catch (e) {
      enqueueSnackbar(errText(e), { variant: "error" });
    } finally {
      setSaving(false);
    }
  }

  const dirty = rpid.trim() !== (originalRpid ?? "");
  const resetFromApp = React.useCallback(() => {
    setRpid(originalRpid ?? "");
  }, [originalRpid]);

  return (
    <Stack spacing={3.5} sx={{ maxWidth: 680 }}>
      <Section
        overline={t("apps.sectionOverline.passkeys", { defaultValue: "Passkeys" })}
        title={t("apps.passkeyTitle", { defaultValue: "Passkeys (WebAuthn)" })}
        desc={t("apps.passkeyDesc", {
          defaultValue:
            "Set the Relying Party ID - the registrable domain users will register passkeys for. Must be a registrable suffix (eTLD+1 or a subdomain of one) of every CORS origin on this app. Leave blank to disable passkeys.",
        })}
      >
        <Alert severity="info" sx={{ fontSize: 13 }}>
          {t("apps.passkeyHint", {
            defaultValue:
              "Examples: example.com (covers app.example.com + staging.example.com), or app.example.com to scope passkeys to that subdomain only. Use 'localhost' for local development.",
          })}
        </Alert>
        {originalRpid && originalRpid !== rpid.trim() && (
          <Alert severity="warning" sx={{ fontSize: 13 }}>
            {t("apps.passkeyRPIDChangeWarning", {
              defaultValue:
                "Changing the RPID will invalidate every passkey already registered for this app - they're cryptographically bound to the old domain. Affected users will need to re-register before they can sign in with a passkey. The other auth methods are unaffected.",
            })}
          </Alert>
        )}
        <TextField
          size="small"
          fullWidth
          label={t("apps.passkeyRPID", { defaultValue: "WebAuthn RPID" })}
          placeholder="example.com"
          value={rpid}
          onChange={(e) => setRpid(e.target.value)}
          helperText={originalRpid === null && rpid === ""
            ? t("apps.passkeyDisabled", { defaultValue: "Passkeys are currently disabled for this app." })
            : ""}
        />
      </Section>
      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={resetFromApp} />
    </Stack>
  );
}

// =====================================================================
// Small shared components
// =====================================================================

// Section renders the editorial overline + title + body pattern used by
// the auth-method tabs. Pass `overline` to surface the small mono label
// above the title; `desc` for the standard grey description line.
function Section({
  overline,
  title,
  desc,
  children,
}: {
  overline?: React.ReactNode;
  title: React.ReactNode;
  desc?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <Stack spacing={1.5}>
      <Box>
        {overline && (
          <Typography
            sx={{
              display: "block",
              fontFamily: "var(--font-mono)",
              textTransform: "uppercase",
              letterSpacing: "0.14em",
              fontSize: 10,
              fontWeight: 500,
              color: "text.disabled",
              mb: 0.75,
            }}
          >
            {overline}
          </Typography>
        )}
        {typeof title === "string" ? (
          <Typography sx={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" }}>
            {title}
          </Typography>
        ) : (
          title
        )}
        {desc && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, maxWidth: 620 }}>
            {desc}
          </Typography>
        )}
      </Box>
      {children}
    </Stack>
  );
}


function CopyableUri(props: { label: string; uri: string; onCopy: () => void; help: string; copyTitle: string }) {
  return (
    <Box>
      <Eyebrow>{props.label}</Eyebrow>
      <Stack direction="row" alignItems="center" spacing={0.5} sx={{ mt: 0.25 }}>
        <Typography sx={{ fontFamily: "var(--font-mono)", fontSize: 12.5, color: "text.primary", wordBreak: "break-all", fontWeight: 500 }}>
          {props.uri}
        </Typography>
        <Tooltip title={props.copyTitle}>
          <IconButton size="small" onClick={props.onCopy} sx={{ p: 0.25 }}>
            <Box component="span" sx={{ fontSize: 12, color: "text.disabled" }}><Copy size={14} strokeWidth={1.75} /></Box>
          </IconButton>
        </Tooltip>
      </Stack>
      <Typography variant="caption" color="text.secondary" sx={{ mt: 0.25, display: "block" }}>{props.help}</Typography>
    </Box>
  );
}

// =====================================================================
// OIDC Provider — ManyRows acts as an OpenID Connect IdP for this app.
// Distinct from the OAuth tab (which sets up sign-in *with* Google/etc.
// for end users); this tab exposes the app over standard OIDC so any
// off-the-shelf OIDC library can integrate without the ManyRows SDK.
// =====================================================================

type OIDCConfigResponse = {
  oidcEnabled: boolean;
  hasOIDCClientSecret: boolean;
  oidcClientSecret?: string; // present ONLY on regenerate
  oidcClientId: string;
  oidcIssuerUrl: string;
  oidcDiscoveryUrl: string;
  oidcRedirectUris: string[];
  oidcPostLogoutRedirectUris: string[];
};

function OIDCProviderCard({ app, cardURL, onError, onSuccess }: CardProps) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const cookieMode = app.transportMode === "cookie";

  const [loading, setLoading] = React.useState(true);
  const [cfg, setCfg] = React.useState<OIDCConfigResponse | null>(null);
  const [enabled, setEnabled] = React.useState(false);
  const [redirects, setRedirects] = React.useState<string[]>([]);
  const [postLogoutUris, setPostLogoutUris] = React.useState<string[]>([]);
  const [newRedirect, setNewRedirect] = React.useState("");
  const [newPostLogout, setNewPostLogout] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [revealedSecret, setRevealedSecret] = React.useState<string | null>(null);
  const [confirmClearOpen, setConfirmClearOpen] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get<OIDCConfigResponse>(`${cardURL}/oidc-config`);
      setCfg(res.data);
      setEnabled(res.data.oidcEnabled);
      setRedirects(res.data.oidcRedirectUris || []);
      setPostLogoutUris(res.data.oidcPostLogoutRedirectUris || []);
    } catch (e) {
      onError(e);
    } finally {
      setLoading(false);
    }
  }, [cardURL, onError]);

  React.useEffect(() => { void load(); }, [load]);

  const dirty = !!cfg && (
    enabled !== cfg.oidcEnabled ||
    redirects.join("|") !== (cfg.oidcRedirectUris || []).join("|") ||
    postLogoutUris.join("|") !== (cfg.oidcPostLogoutRedirectUris || []).join("|")
  );

  async function copyToClipboard(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      enqueueSnackbar(t("apps.copied", { label }), { variant: "success" });
    } catch {
      enqueueSnackbar(t("apps.copyFailed", { defaultValue: "Copy failed" }), { variant: "error" });
    }
  }

  function isValidHttpURL(s: string): boolean {
    try {
      const u = new URL(s);
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  }

  function addRedirect() {
    const v = newRedirect.trim();
    if (!v) return;
    if (!isValidHttpURL(v)) {
      enqueueSnackbar(t("apps.oidc.invalidUri", { defaultValue: "Redirect URI must be a valid http(s) URL" }), { variant: "warning" });
      return;
    }
    if (redirects.includes(v)) return;
    setRedirects([...redirects, v]);
    setNewRedirect("");
  }

  function addPostLogout() {
    const v = newPostLogout.trim();
    if (!v) return;
    if (!isValidHttpURL(v)) {
      enqueueSnackbar(t("apps.oidc.invalidUri", { defaultValue: "Redirect URI must be a valid http(s) URL" }), { variant: "warning" });
      return;
    }
    if (postLogoutUris.includes(v)) return;
    setPostLogoutUris([...postLogoutUris, v]);
    setNewPostLogout("");
  }

  async function saveConfig() {
    if (!cfg) return;
    if (enabled && redirects.length === 0) {
      onError(new Error(t("apps.oidc.redirectUrisRequired", { defaultValue: "Add at least one Redirect URI before enabling OIDC." })));
      return;
    }
    setSaving(true);
    try {
      const res = await axios.put<OIDCConfigResponse>(`${cardURL}/oidc-config`, {
        enabled,
        redirectUris: redirects,
        postLogoutRedirectUris: postLogoutUris,
      });
      setCfg(res.data);
      setEnabled(res.data.oidcEnabled);
      setRedirects(res.data.oidcRedirectUris || []);
      setPostLogoutUris(res.data.oidcPostLogoutRedirectUris || []);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  async function regenerateSecret() {
    setSaving(true);
    try {
      const res = await axios.put<OIDCConfigResponse>(`${cardURL}/oidc-config`, {
        regenerateSecret: true,
      });
      setCfg(res.data);
      if (res.data.oidcClientSecret) {
        setRevealedSecret(res.data.oidcClientSecret);
      }
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  async function clearSecret() {
    setConfirmClearOpen(false);
    setSaving(true);
    try {
      const res = await axios.put<OIDCConfigResponse>(`${cardURL}/oidc-config`, {
        clearSecret: true,
      });
      setCfg(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  function resetFromCfg() {
    if (!cfg) return;
    setEnabled(cfg.oidcEnabled);
    setRedirects(cfg.oidcRedirectUris || []);
    setPostLogoutUris(cfg.oidcPostLogoutRedirectUris || []);
    setNewRedirect("");
    setNewPostLogout("");
  }

  if (loading || !cfg) return <Loader />;

  return (
    <Stack
      divider={<Box sx={{ height: "1px", bgcolor: "divider", my: 1 }} />}
      spacing={3.5}
      sx={{ maxWidth: 680 }}
    >
      <Section
        overline={t("apps.sectionOverline.oidcProvider", { defaultValue: "OIDC provider" })}
        title={t("apps.oidc.title", { defaultValue: "OpenID Connect provider" })}
        desc={t("apps.oidc.desc", {
          defaultValue:
            "Expose this app over standard OpenID Connect so any off-the-shelf OIDC client library (next-auth, passport-openidconnect, Spring Security, etc.) can authenticate users without the ManyRows SDK. Coexists with the SDK path — both work in parallel.",
        })}
      >
        {!cookieMode && (
          <Alert severity="warning" sx={{ mb: 1 }}>
            {t("apps.oidc.cookieModeRequired", {
              defaultValue:
                "OIDC requires Cookie transport mode. Switch this app's transport mode in the General tab before enabling.",
            })}
          </Alert>
        )}

        <FormControlLabel
          control={
            <Switch
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              disabled={saving || !cookieMode}
            />
          }
          label={
            <Stack spacing={0}>
              <Typography variant="body2" sx={{ fontWeight: 500 }}>
                {t("apps.oidc.enableLabel", { defaultValue: "Enable OIDC provider for this app" })}
              </Typography>
              {enabled && redirects.length === 0 && (
                <Typography variant="caption" color="text.secondary">
                  {t("apps.oidc.redirectUrisRequiredHint", { defaultValue: "Add at least one Redirect URI before saving." })}
                </Typography>
              )}
            </Stack>
          }
          sx={{ ml: 0 }}
        />
      </Section>

      <Section
        overline={t("apps.sectionOverline.endpoints", { defaultValue: "Endpoints" })}
        title={t("apps.oidc.endpointsTitle", { defaultValue: "Integration endpoints" })}
        desc={t("apps.oidc.endpointsDesc", {
          defaultValue: "Paste these into your OIDC client library configuration.",
        })}
      >
        <CopyableUri
          label={t("apps.oidc.discoveryUrl", { defaultValue: "Discovery URL" })}
          uri={cfg.oidcDiscoveryUrl}
          onCopy={() => copyToClipboard(cfg.oidcDiscoveryUrl, "Discovery URL")}
          help={t("apps.oidc.discoveryUrlHelp", { defaultValue: "Most OIDC libraries take this single URL and self-configure." })}
          copyTitle={t("apps.copyDiscoveryUrl", { defaultValue: "Copy discovery URL" })}
        />
        <CopyableUri
          label={t("apps.oidc.issuerUrl", { defaultValue: "Issuer URL" })}
          uri={cfg.oidcIssuerUrl}
          onCopy={() => copyToClipboard(cfg.oidcIssuerUrl, "Issuer URL")}
          help={t("apps.oidc.issuerUrlHelp", { defaultValue: "The iss claim on issued id_tokens. Matches the discovery doc's issuer field." })}
          copyTitle={t("apps.copyIssuerUrl", { defaultValue: "Copy issuer URL" })}
        />
        <CopyableUri
          label={t("apps.oidc.clientId", { defaultValue: "Client ID" })}
          uri={cfg.oidcClientId}
          onCopy={() => copyToClipboard(cfg.oidcClientId, "Client ID")}
          help={t("apps.oidc.clientIdHelp", { defaultValue: "Stable per app. Send as client_id at /authorize and /token." })}
          copyTitle={t("apps.copyClientId", { defaultValue: "Copy client ID" })}
        />
      </Section>

      <Section
        overline={t("apps.sectionOverline.clientSecret", { defaultValue: "Client secret" })}
        title={t("apps.oidc.clientSecretTitle", { defaultValue: "Client secret" })}
        desc={t("apps.oidc.clientSecretDesc", {
          defaultValue: "Confidential clients (backend code) authenticate at /token with a secret. Public clients (browser/mobile, PKCE-only) leave the secret empty.",
        })}
      >
        <Stack direction="row" alignItems="center" spacing={1}>
          {cfg.hasOIDCClientSecret ? (
            <StatusChip size="xs" label={t("apps.oidc.secretConfigured", { defaultValue: "Configured" })} severity="success" />
          ) : (
            <StatusChip size="xs" label={t("apps.oidc.publicClient", { defaultValue: "Public client (PKCE-only)" })} severity="warning" />
          )}
          <Box sx={{ flexGrow: 1 }} />
          {/* Regen + Clear are disabled while there are unsaved edits
              above: each operation does its own PUT and would otherwise
              silently discard the user's pending toggle / URI changes. */}
          <Tooltip
            title={dirty ? t("apps.oidc.saveChangesFirst", { defaultValue: "Save your pending changes first." }) : ""}
          >
            <span>
              <Button
                size="small"
                variant="outlined"
                onClick={() => void regenerateSecret()}
                disabled={saving || dirty}
                sx={{ textTransform: "none" }}
              >
                {cfg.hasOIDCClientSecret
                  ? t("apps.oidc.rotateSecret", { defaultValue: "Rotate secret" })
                  : t("apps.oidc.generateSecret", { defaultValue: "Generate secret" })}
              </Button>
            </span>
          </Tooltip>
          {cfg.hasOIDCClientSecret && (
            <Tooltip
              title={dirty ? t("apps.oidc.saveChangesFirst", { defaultValue: "Save your pending changes first." }) : ""}
            >
              <span>
                <Button
                  size="small"
                  color="error"
                  onClick={() => setConfirmClearOpen(true)}
                  disabled={saving || dirty}
                  sx={{ textTransform: "none" }}
                >
                  {t("apps.oidc.downgradeToPublic", { defaultValue: "Clear (public)" })}
                </Button>
              </span>
            </Tooltip>
          )}
        </Stack>
      </Section>

      <Section
        overline={t("apps.sectionOverline.redirectUris", { defaultValue: "Redirect URIs" })}
        title={t("apps.oidc.redirectUrisTitle", { defaultValue: "Redirect URIs" })}
        desc={t("apps.oidc.redirectUrisDesc", {
          defaultValue: "Exact-match allowlist. The RP's redirect_uri at /authorize must match one of these exactly.",
        })}
      >
        <UriListEditor
          uris={redirects}
          newUri={newRedirect}
          setNewUri={setNewRedirect}
          onAdd={addRedirect}
          onRemove={(u) => setRedirects(redirects.filter((x) => x !== u))}
          placeholder="https://customer-app.example.com/oidc/callback"
          disabled={saving}
        />
      </Section>

      <Section
        overline={t("apps.sectionOverline.postLogoutUris", { defaultValue: "Post-logout redirect URIs" })}
        title={t("apps.oidc.postLogoutTitle", { defaultValue: "Post-logout redirect URIs" })}
        desc={t("apps.oidc.postLogoutDesc", {
          defaultValue: "Optional. Exact-match allowlist for post_logout_redirect_uri on /oidc/end-session.",
        })}
      >
        <UriListEditor
          uris={postLogoutUris}
          newUri={newPostLogout}
          setNewUri={setNewPostLogout}
          onAdd={addPostLogout}
          onRemove={(u) => setPostLogoutUris(postLogoutUris.filter((x) => x !== u))}
          placeholder="https://customer-app.example.com/signed-out"
          disabled={saving}
        />
      </Section>

      <SaveBar dirty={dirty} saving={saving} onSave={() => void saveConfig()} onDiscard={resetFromCfg} />

      {/* Show-once secret dialog */}
      <Dialog open={revealedSecret !== null} onClose={() => setRevealedSecret(null)} maxWidth="sm" fullWidth>
        <DialogTitle>{t("apps.oidc.secretRevealedTitle", { defaultValue: "Client secret generated" })}</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            {t("apps.oidc.secretRevealedDesc", {
              defaultValue:
                "Copy this secret and store it somewhere safe. It will NEVER be shown again — only its hash is kept. If you lose it, generate a new one (which invalidates this one).",
            })}
          </DialogContentText>
          <TextField
            fullWidth
            multiline
            value={revealedSecret || ""}
            InputProps={{ readOnly: true, sx: { fontFamily: "var(--font-mono)", fontSize: 13 } }}
            onFocus={(e) => e.target.select()}
          />
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              if (revealedSecret) void copyToClipboard(revealedSecret, "Client secret");
            }}
            startIcon={<Copy size={14} strokeWidth={1.75} />}
          >
            {t("apps.copy", { defaultValue: "Copy" })}
          </Button>
          <Button onClick={() => setRevealedSecret(null)} variant="contained">
            {t("apps.oidc.secretRevealedDone", { defaultValue: "I've saved it" })}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Confirm-clear secret dialog */}
      <Dialog open={confirmClearOpen} onClose={() => setConfirmClearOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>{t("apps.oidc.clearConfirmTitle", { defaultValue: "Downgrade to public client?" })}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("apps.oidc.clearConfirmDesc", {
              defaultValue:
                "Clearing the secret turns this app into a public client (PKCE-only). Existing integrations that send a client_secret at /token will fail until reconfigured.",
            })}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmClearOpen(false)}>{t("cancel", { defaultValue: "Cancel" })}</Button>
          <Button onClick={() => void clearSecret()} color="error" variant="contained">
            {t("apps.oidc.clearConfirmAction", { defaultValue: "Clear secret" })}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}

// UriListEditor — shared list-editor for redirect_uris + post_logout_uris.
function UriListEditor({
  uris,
  newUri,
  setNewUri,
  onAdd,
  onRemove,
  placeholder,
  disabled,
}: {
  uris: string[];
  newUri: string;
  setNewUri: (v: string) => void;
  onAdd: () => void;
  onRemove: (u: string) => void;
  placeholder: string;
  disabled?: boolean;
}) {
  return (
    <Stack spacing={1}>
      <Stack direction="row" spacing={1}>
        <TextField
          size="small"
          fullWidth
          value={newUri}
          onChange={(e) => setNewUri(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              onAdd();
            }
          }}
          placeholder={placeholder}
          disabled={disabled}
        />
        <Button onClick={onAdd} disabled={disabled || newUri.trim() === ""} startIcon={<Plus size={14} strokeWidth={1.75} />} sx={{ textTransform: "none", whiteSpace: "nowrap" }}>
          Add
        </Button>
      </Stack>
      {uris.length === 0 ? (
        <Typography variant="caption" color="text.disabled">
          None configured.
        </Typography>
      ) : (
        <Stack spacing={0.75}>
          {uris.map((u) => (
            <Stack key={u} direction="row" alignItems="center" spacing={1} sx={{
              p: 1,
              borderRadius: 1,
              bgcolor: "action.hover",
            }}>
              <Typography sx={{ fontFamily: "var(--font-mono)", fontSize: 12.5, flexGrow: 1, wordBreak: "break-all" }}>
                {u}
              </Typography>
              <Tooltip title="Remove">
                <IconButton size="small" onClick={() => onRemove(u)} disabled={disabled}>
                  <Trash2 size={14} strokeWidth={1.75} />
                </IconButton>
              </Tooltip>
            </Stack>
          ))}
        </Stack>
      )}
    </Stack>
  );
}

// =====================================================================
// QR sign-in — cross-device passwordless. ManyRows hosts the QR
// display + phone approve flow; AppKit shows a "Sign in with phone"
// button on the login screen when this is on.
// =====================================================================

function QRSignInCard({ app, cardURL, onSaved, onError, onSuccess }: CardProps) {
  const { t } = useTranslation();
  const { enqueueSnackbar } = useSnackbar();

  const hasAppURL = !!app.appUrl && app.appUrl.trim().length > 0;
  const [enabled, setEnabled] = React.useState(!!app.qrSignInEnabled);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => { setEnabled(!!app.qrSignInEnabled); }, [app.qrSignInEnabled]);

  const dirty = enabled !== !!app.qrSignInEnabled;

  // The hosted /qr-sign-in URL pattern. Server-computed (lives at the
  // PUBLIC per-app path /x/<slug>/apps/<id>/qr-sign-in, NOT under
  // /admin/) so the UI doesn't try to derive it from cardURL.
  // Customers link their "Sign in with phone" entry-point here; AppKit
  // auto-renders a button once enabled, but customers integrating
  // without AppKit need the URL.
  const qrSignInURL = app.qrSignInUrl || "";

  async function copyToClipboard(text: string, label: string) {
    try {
      await navigator.clipboard.writeText(text);
      enqueueSnackbar(t("apps.copied", { label }), { variant: "success" });
    } catch {
      enqueueSnackbar(t("apps.copyFailed", { defaultValue: "Copy failed" }), { variant: "error" });
    }
  }

  async function save() {
    if (enabled && !hasAppURL) {
      onError(new Error(t("apps.qr.appUrlRequired", { defaultValue: "Set App URL under General → App URL before enabling QR sign-in." })));
      return;
    }
    setSaving(true);
    try {
      const res = await axios.put<App>(`${cardURL}/qr-sign-in-config`, { enabled });
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Stack
      divider={<Box sx={{ height: "1px", bgcolor: "divider", my: 1 }} />}
      spacing={3.5}
      sx={{ maxWidth: 680 }}
    >
      <Section
        overline={t("apps.sectionOverline.qrSignIn", { defaultValue: "QR sign-in" })}
        title={t("apps.qr.title", { defaultValue: "Cross-device sign-in (QR)" })}
        desc={t("apps.qr.desc", {
          defaultValue:
            "Lets users sign in on a desktop by scanning a QR code with their phone. The phone (already signed in) approves; the desktop receives tokens. AppKit renders a 'Sign in with phone' button on the login screen when this is on.",
        })}
      >
        {!hasAppURL && (
          <Alert severity="warning" sx={{ mb: 1 }}>
            {t("apps.qr.appUrlRequiredHint", {
              defaultValue:
                "QR sign-in requires App URL to be set (under General → App URL). The desktop success flow redirects there with tokens in the URL fragment; without it there's nowhere safe to land.",
            })}
          </Alert>
        )}
        <FormControlLabel
          control={
            <Switch
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              disabled={saving || (!hasAppURL && !app.qrSignInEnabled)}
            />
          }
          label={
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              {t("apps.qr.enableLabel", { defaultValue: "Enable QR sign-in for this app" })}
            </Typography>
          }
          sx={{ ml: 0 }}
        />
      </Section>

      <Section
        overline={t("apps.sectionOverline.qrIntegrate", { defaultValue: "Integrate" })}
        title={t("apps.qr.integrateTitle", { defaultValue: "Hosted sign-in URL" })}
        desc={t("apps.qr.integrateDesc", {
          defaultValue:
            "Link to this from your app to bootstrap the QR flow. After the user scans + approves on their phone, tokens land in the URL fragment at the return_to target.",
        })}
      >
        {qrSignInURL ? (
          <CopyableUri
            label={t("apps.qr.urlLabel", { defaultValue: "QR sign-in URL" })}
            uri={qrSignInURL}
            onCopy={() => copyToClipboard(qrSignInURL, "QR URL")}
            help={t("apps.qr.urlHelp", {
              defaultValue:
                "Append ?return_to=<your-callback> when linking. return_to host must match App URL.",
            })}
            copyTitle={t("apps.copyQRUrl", { defaultValue: "Copy QR URL" })}
          />
        ) : (
          <Typography variant="caption" color="text.secondary">
            {t("apps.qr.urlPending", {
              defaultValue: "URL will appear once MANYROWS_BASE_URL is pinned (happens on first admin register).",
            })}
          </Typography>
        )}
      </Section>

      <SaveBar dirty={dirty} saving={saving} onSave={() => void save()} onDiscard={() => setEnabled(!!app.qrSignInEnabled)} />
    </Stack>
  );
}
