import * as React from "react";
import axios from "axios";
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  IconButton,
  Radio,
  RadioGroup,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { X } from "lucide-react";
import Eyebrow from "../components/Eyebrow.tsx";
import { Link as RouterLink } from "react-router-dom";
import { useTranslation, Trans } from "react-i18next";
import type { App } from "./AppAuthMethods.tsx";
import AppCookieDomainCard from "./AppCookieDomainCard.tsx";
import SaveBar from "../components/SaveBar.tsx";

// Session config - split into two top-level tabs at the AppSecurity
// level: Session transport (how the token reaches the browser) and
// Session lifetime (TTLs). Each pane is exported individually so
// AppSecurity can mount them as siblings rather than nesting tabs.
interface Props {
  app: App;
  cardURL: string;
  workspaceCookieDomain?: string | null;
  workspaceID: string;
  onSaved: (a: App) => void;
  onSuccess: () => void;
  onError: (e: unknown) => void;
}

const DEFAULT_TTL_MINUTES = 7 * 24 * 60; // 7 days

export function SessionTransportTab(props: Props) {
  return (
    <Box sx={{ maxWidth: 720, pb: 6 }}>
      <SessionTransportPane {...props} />
    </Box>
  );
}

export function SessionLifetimeTab(props: Props) {
  return (
    <Box sx={{ maxWidth: 720, pb: 6 }}>
      <LifetimePane {...props} />
    </Box>
  );
}

// =====================================================================
// SessionTransportPane - the consolidated Transport UI. The radio
// PATCHes the dedicated /transport-mode endpoint; the cookie-mode
// config card saves through its existing endpoint below the radio.
// The chosen mode is also returned in the /a/me boot response so
// AppKit configures itself automatically.
// =====================================================================

type Transport = "local" | "cookie";

function currentTransport(app: App): Transport {
  return app.transportMode ?? "local";
}

function SessionTransportPane({
  app,
  cardURL,
  workspaceCookieDomain,
  workspaceID,
  onSaved,
  onSuccess,
  onError,
}: Props) {
  const { t } = useTranslation();
  // Local radio state - not persisted until the user hits Save. The
  // per-mode reveal panes below switch on the *persisted* value
  // (currentTransport(app)), so picking a different radio doesn't
  // surface that mode's config until the choice is committed.
  const [transport, setTransport] = React.useState<Transport>(currentTransport(app));
  const [saving, setSaving] = React.useState(false);
  React.useEffect(() => {
    setTransport(currentTransport(app));
  }, [app]);

  const persisted = currentTransport(app);
  const dirty = transport !== persisted;

  const [instructionsOpen, setInstructionsOpen] = React.useState(false);

  async function save() {
    if (!dirty || saving) return;
    setSaving(true);
    try {
      const res = await axios.put<App>(`${cardURL}/transport-mode`, { transportMode: transport });
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Stack spacing={3} sx={{ maxWidth: 680 }}>
      <Stack spacing={2}>
        <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 620 }}>
          {t("sessionTransport.intro", { defaultValue: "How the session token is delivered to the user's browser. AppKit picks up this setting from the boot response, so the SDK doesn't need a separate prop on the customer side." })}
        </Typography>

          <RadioGroup
            value={transport}
            onChange={(e) => setTransport(e.target.value as Transport)}
          >
            <FormControlLabel
              value="local"
              disabled={saving}
              control={<Radio />}
              label={
                <Stack>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                    {t("sessionTransport.localTitle", { defaultValue: "Local (browser storage)" })}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    <Trans i18nKey="sessionTransport.localDesc" components={{ code: <code /> }}>
                      ManyRows issues a JWT to your frontend, which keeps it in localStorage and sends it as a <code>Bearer</code> token. Simplest to set up - no backend code, no DNS - but the token is visible to any JS running on your origin.
                    </Trans>
                  </Typography>
                </Stack>
              }
              sx={{ alignItems: "flex-start", ml: 0, mt: 1 }}
            />

            <FormControlLabel
              value="cookie"
              disabled={saving}
              control={<Radio />}
              label={
                <Stack>
                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                    {t("sessionTransport.cookieTitle", { defaultValue: "First-party cookie (same-host deploy OR custom-domain CNAME)" })}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    <Trans i18nKey="sessionTransport.cookieDesc" components={{ code: <code /> }}>
                      ManyRows sets an <code>HttpOnly; Secure; SameSite=Lax</code> session cookie on a host that's same-site as your app (e.g. <code>auth.yourdomain.com</code> alongside <code>www.yourdomain.com</code>). The token never touches JS. Works whether ManyRows is reached via a custom-domain CNAME or a same-host deploy. Configure the cookie domain below; setup details for the custom-domain shape are in the dialog.
                    </Trans>
                  </Typography>
                </Stack>
              }
              sx={{ alignItems: "flex-start", ml: 0, mt: 1.5 }}
            />

          </RadioGroup>

          {dirty && (
            <Alert severity="warning" sx={{ fontSize: 13 }}>
              {t("sessionTransport.dirtyWarning", { defaultValue: "You've picked a different transport than what's currently configured. The change isn't applied until you save - switching modes also clears the per-mode setup panel below so you can configure the new mode after committing." })}
            </Alert>
          )}

      </Stack>
      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={() => setTransport(persisted as Transport)} />

      {persisted === "local" && (
        <Box
          sx={{
            border: "1px dashed",
            borderColor: "divider",
            borderRadius: 2,
            px: 3,
            py: 2.5,
          }}
        >
          <Eyebrow sx={{ mb: 0.75 }}>{t("sessionTransport.noSetupTitle", { defaultValue: "No extra setup" })}</Eyebrow>
          <Typography variant="body2" color="text.secondary">
            <Trans i18nKey="sessionTransport.noSetupBody">
              Local mode is the AppKit default. There's nothing to configure here - embed AppKit on your site and sign-in just works. To switch later, pick First-party cookie above.
            </Trans>
          </Typography>
        </Box>
      )}

      {persisted === "cookie" && (
        <Stack spacing={3}>
          <AppCookieDomainCard
            app={app}
            cardURL={cardURL}
            workspaceCookieDomain={workspaceCookieDomain ?? null}
            onSaved={onSaved}
            onSuccess={onSuccess}
            onError={onError}
          />
          <CookieStrictnessCard
            app={app}
            cardURL={cardURL}
            onSaved={onSaved}
            onSuccess={onSuccess}
            onError={onError}
          />
          <Stack spacing={2.5} sx={{ pt: 1 }}>
            <Box>
              <Eyebrow sx={{ mb: 0.75 }}>{t("sessionTransport.customDomainTitle", { defaultValue: "Custom-domain setup (optional)" })}</Eyebrow>
              <Typography variant="body2" color="text.secondary">
                <Trans i18nKey="sessionTransport.customDomainBody" components={{ code: <code /> }}>
                  If ManyRows isn't already on a same-site host with your app, you can CNAME a subdomain (e.g. <code>auth.yourdomain.com</code>) to this install. The dialog covers DNS, TLS, and Cloudflare-specific gotchas.
                </Trans>
              </Typography>
              <Box sx={{ pt: 1 }}>
                <Button
                  variant="outlined"
                  onClick={() => setInstructionsOpen(true)}

                >
                  {t("sessionTransport.showInstructions", { defaultValue: "Show setup instructions" })}
                </Button>
              </Box>
            </Box>
          </Stack>
        </Stack>
      )}

      <CustomDomainInstructionsDialog
        open={instructionsOpen}
        onClose={() => setInstructionsOpen(false)}
        workspaceID={workspaceID}
      />
    </Stack>
  );
}

// =====================================================================
// LifetimePane - the existing TTL form, extracted from the top-level
// card so the horizontal tabs can swap panes cleanly.
// =====================================================================

// minutesField is a small helper for the four lifetime inputs. Each
// is identical save for label/placeholder/help - extracted so the
// pane body stays readable.
function minutesField(opts: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  disabled: boolean;
  placeholder: string;
  helper: string;
  invalid: boolean;
  invalidText: string;
}) {
  return (
    <TextField
      label={opts.label}
      size="small"
      type="number"
      value={opts.value}
      onChange={(e) => opts.onChange(e.target.value)}
      disabled={opts.disabled}
      placeholder={opts.placeholder}
      error={opts.invalid}
      helperText={opts.invalid ? opts.invalidText : opts.helper}
      sx={{ maxWidth: 360 }}
    />
  );
}

const DEFAULT_IDLE_TIMEOUT_LABEL = "off";
const DEFAULT_REMEMBER_ME_MINUTES = 30 * 24 * 60; // 30 days
const DEFAULT_ACCESS_TOKEN_MINUTES = 15;
const DEFAULT_MAX_SESSIONS = 5;

function LifetimePane({ app, cardURL, onSaved, onSuccess, onError }: Props) {
  const { t } = useTranslation();

  const init = (n?: number | null) => (n != null ? String(n) : "");
  const [sessionTtl, setSessionTtl] = React.useState(init(app.sessionTtlMinutes));
  const [idleTimeout, setIdleTimeout] = React.useState(init(app.idleTimeoutMinutes));
  const [rememberMeTtl, setRememberMeTtl] = React.useState(init(app.rememberMeTtlMinutes));
  const [accessTokenTtl, setAccessTokenTtl] = React.useState(init(app.accessTokenTtlMinutes));
  const [maxSessions, setMaxSessions] = React.useState(init(app.maxSessionsPerUser));
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => setSessionTtl(init(app.sessionTtlMinutes)), [app.sessionTtlMinutes]);
  React.useEffect(() => setIdleTimeout(init(app.idleTimeoutMinutes)), [app.idleTimeoutMinutes]);
  React.useEffect(() => setRememberMeTtl(init(app.rememberMeTtlMinutes)), [app.rememberMeTtlMinutes]);
  React.useEffect(() => setAccessTokenTtl(init(app.accessTokenTtlMinutes)), [app.accessTokenTtlMinutes]);
  React.useEffect(() => setMaxSessions(init(app.maxSessionsPerUser)), [app.maxSessionsPerUser]);

  const parse = (raw: string): { value: number | null; invalid: boolean } => {
    const trimmed = raw.trim();
    if (trimmed === "") return { value: null, invalid: false };
    const n = parseInt(trimmed, 10);
    return { value: n, invalid: Number.isNaN(n) || n < 0 };
  };

  const session = parse(sessionTtl);
  const idle = parse(idleTimeout);
  const remember = parse(rememberMeTtl);
  const access = parse(accessTokenTtl);
  const max = parse(maxSessions);

  const invalid = session.invalid || idle.invalid || remember.invalid || access.invalid || max.invalid;
  const dirty =
    (session.value ?? 0) !== (app.sessionTtlMinutes ?? 0) ||
    (idle.value ?? 0) !== (app.idleTimeoutMinutes ?? 0) ||
    (remember.value ?? 0) !== (app.rememberMeTtlMinutes ?? 0) ||
    (access.value ?? 0) !== (app.accessTokenTtlMinutes ?? 0) ||
    (max.value ?? 0) !== (app.maxSessionsPerUser ?? 0);

  async function save() {
    if (invalid) return;
    setSaving(true);
    try {
      const payload = {
        sessionTtlMinutes: session.value && session.value > 0 ? session.value : 0,
        idleTimeoutMinutes: idle.value && idle.value > 0 ? idle.value : 0,
        rememberMeTtlMinutes: remember.value && remember.value > 0 ? remember.value : 0,
        accessTokenTtlMinutes: access.value && access.value > 0 ? access.value : 0,
        maxSessionsPerUser: max.value && max.value > 0 ? max.value : 0,
      };
      const res = await axios.patch<App>(`${cardURL}/`, payload);
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Stack spacing={2.5} sx={{ maxWidth: 680 }}>
      <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 620 }}>
        {t("sessionLifetime.intro", { defaultValue: "How long an end-user's session stays valid before they have to sign in again." })}
      </Typography>

        {minutesField({
          label: t("apps.detail.sessionTtl", { defaultValue: "Session timeout (minutes)" }),
          value: sessionTtl,
          onChange: setSessionTtl,
          disabled: saving,
          placeholder: String(DEFAULT_TTL_MINUTES),
          helper: t("apps.detail.sessionTtlDesc", {
            defaultValue: "Absolute lifetime. Leave blank for the default (7 days / 10080 minutes).",
          }),
          invalid: session.invalid,
          invalidText: t("apps.detail.minutesInvalid", { defaultValue: "Must be a non-negative integer" }),
        })}

        {minutesField({
          label: t("apps.detail.idleTimeout", { defaultValue: "Idle timeout (minutes)" }),
          value: idleTimeout,
          onChange: setIdleTimeout,
          disabled: saving,
          placeholder: DEFAULT_IDLE_TIMEOUT_LABEL,
          helper: t("apps.detail.idleTimeoutDesc", {
            defaultValue:
              "Refresh is refused when the session hasn't been active for this many minutes; the session then dies once the current access token expires. Leave blank to disable idle enforcement.",
          }),
          invalid: idle.invalid,
          invalidText: t("apps.detail.minutesInvalid", { defaultValue: "Must be a non-negative integer" }),
        })}

        {minutesField({
          label: t("apps.detail.rememberMeTtl", { defaultValue: "Remember-me lifetime (minutes)" }),
          value: rememberMeTtl,
          onChange: setRememberMeTtl,
          disabled: saving,
          placeholder: String(DEFAULT_REMEMBER_ME_MINUTES),
          helper: t("apps.detail.rememberMeTtlDesc", {
            defaultValue:
              "Applied when the user opted into \"Keep me signed in\" at login. Leave blank for the default (30 days / 43200 minutes).",
          }),
          invalid: remember.invalid,
          invalidText: t("apps.detail.minutesInvalid", { defaultValue: "Must be a non-negative integer" }),
        })}

        {minutesField({
          label: t("apps.detail.accessTokenTtl", { defaultValue: "Access-token lifetime (minutes)" }),
          value: accessTokenTtl,
          onChange: setAccessTokenTtl,
          disabled: saving,
          placeholder: String(DEFAULT_ACCESS_TOKEN_MINUTES),
          helper: t("apps.detail.accessTokenTtlDesc", {
            defaultValue:
              "Trades JWT-replay window against refresh-call frequency. Don't drop below ~5 minutes unless your SDK can handle refresh storms. Leave blank for the default (15 minutes).",
          }),
          invalid: access.invalid,
          invalidText: t("apps.detail.minutesInvalid", { defaultValue: "Must be a non-negative integer" }),
        })}

        {minutesField({
          label: t("apps.detail.maxSessions", { defaultValue: "Max active sessions per user" }),
          value: maxSessions,
          onChange: setMaxSessions,
          disabled: saving,
          placeholder: String(DEFAULT_MAX_SESSIONS),
          helper: t("apps.detail.maxSessionsDesc", {
            defaultValue:
              "Logging in beyond this cap prunes the user's oldest session for this app. Set 1 for single-device apps; raise it for productivity tools where users span phone + laptop + tablet. Leave blank for the default (5).",
          }),
          invalid: max.invalid,
          invalidText: t("apps.detail.minutesInvalid", { defaultValue: "Must be a non-negative integer" }),
        })}

      <Alert severity="info" sx={{ fontSize: 13 }}>
        {t("sessionLifetime.existingNote", { defaultValue: "Existing sessions stay alive until they reach the new absolute limit; nothing is invalidated retroactively." })}
      </Alert>

      <SaveBar
        dirty={dirty}
        saving={saving}
        onSave={save}
        onDiscard={() => {
          setSessionTtl(init(app.sessionTtlMinutes));
          setIdleTimeout(init(app.idleTimeoutMinutes));
          setRememberMeTtl(init(app.rememberMeTtlMinutes));
          setAccessTokenTtl(init(app.accessTokenTtlMinutes));
          setMaxSessions(init(app.maxSessionsPerUser));
        }}
        disabled={invalid}
      />
    </Stack>
  );
}

// =====================================================================
// CookieStrictnessCard - toggles the SameSite attribute on session
// cookies between "lax" (default, works with magic links / OAuth /
// link-based reset) and "strict" (no inbound cross-site GET ever
// carries the session - marginal CSRF hardening for installs that
// have no email-link flows).
//
// The radio is disabled when the app's currently-enabled auth methods
// would silently break under Strict (magic links / any OAuth provider).
// Server-side validation is the load-bearing check; this just shows
// the operator why.
// =====================================================================

function CookieStrictnessCard({ app, cardURL, onSaved, onSuccess, onError }: {
  app: App;
  cardURL: string;
  onSaved: (a: App) => void;
  onSuccess: () => void;
  onError: (e: unknown) => void;
}) {
  const { t } = useTranslation();
  type SameSite = "lax" | "strict";
  const persisted: SameSite = app.sessionCookieSameSite ?? "lax";
  const [value, setValue] = React.useState<SameSite>(persisted);
  const [saving, setSaving] = React.useState(false);
  React.useEffect(() => { setValue(persisted); }, [persisted]);

  // Strict precondition: no link-based auth flow active. Mirror the
  // server-side check so the UI shows why Strict is unavailable.
  const blockers: string[] = [];
  if (app.primaryAuthMethod === "magicLink") blockers.push(t("cookieStrictness.blocker.magicLinks", { defaultValue: "magic links" }));
  if (app.authMethodGoogle) blockers.push(t("cookieStrictness.blocker.google", { defaultValue: "Google sign-in" }));
  if (app.authMethodApple) blockers.push(t("cookieStrictness.blocker.apple", { defaultValue: "Apple sign-in" }));
  if (app.authMethodMicrosoft) blockers.push(t("cookieStrictness.blocker.microsoft", { defaultValue: "Microsoft sign-in" }));
  if (app.authMethodGithub) blockers.push(t("cookieStrictness.blocker.github", { defaultValue: "GitHub sign-in" }));
  if (app.authMethodKakao) blockers.push(t("cookieStrictness.blocker.kakao", { defaultValue: "Kakao sign-in" }));
  if (app.authMethodNaver) blockers.push(t("cookieStrictness.blocker.naver", { defaultValue: "Naver sign-in" }));
  const strictDisabled = blockers.length > 0;
  const dirty = value !== persisted;

  async function save() {
    if (!dirty || saving) return;
    setSaving(true);
    try {
      const res = await axios.put<App>(`${cardURL}/session-cookie-samesite`, {
        sessionCookieSameSite: value,
      });
      onSaved(res.data);
      onSuccess();
    } catch (e) {
      onError(e);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Stack spacing={2} sx={{ maxWidth: 680 }}>
      <Box>
        <Typography
          sx={{
            display: "inline-flex",
            alignItems: "center",
            gap: 1,
            fontFamily: "var(--font-mono)",
            textTransform: "uppercase",
            letterSpacing: "0.14em",
            fontSize: 10,
            fontWeight: 500,
            color: "text.disabled",
            mb: 0.75,
          }}
        >
          {t("cookieStrictness.overline", { defaultValue: "Sessions" })}
        </Typography>
        <Typography sx={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" }}>
          {t("cookieStrictness.title", { defaultValue: "Cookie strictness" })}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5, maxWidth: 620 }}>
          {t("cookieStrictness.description", { defaultValue: "SameSite attribute on the session cookies. Lax (the default) works with every auth flow. Strict adds a marginal CSRF hardening but breaks any flow that lands the user on this app via a top-level cross-site GET - magic links, OAuth redirects, link-based password resets." })}
        </Typography>
      </Box>

        <RadioGroup
          value={value}
          onChange={(e) => setValue(e.target.value as SameSite)}
        >
          <FormControlLabel
            value="lax"
            disabled={saving}
            control={<Radio />}
            label={
              <Stack>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                  {t("cookieStrictness.laxTitle", { defaultValue: "Lax (default)" })}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {t("cookieStrictness.laxDesc", { defaultValue: "Cookies ride along on top-level navigation from another site. Required for magic links, OAuth, and any \"click a link in email → land logged in\" flow." })}
                </Typography>
              </Stack>
            }
            sx={{ alignItems: "flex-start", ml: 0, mt: 1 }}
          />

          <FormControlLabel
            value="strict"
            disabled={saving || (strictDisabled && value !== "strict")}
            control={<Radio />}
            label={
              <Stack>
                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                  {t("cookieStrictness.strictTitle", { defaultValue: "Strict" })}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {t("cookieStrictness.strictDesc", { defaultValue: "Cookies are sent only on same-site requests. A user who clicks a link from another site lands logged-out and has to navigate within this app once before the cookie returns." })}
                </Typography>
              </Stack>
            }
            sx={{ alignItems: "flex-start", ml: 0, mt: 1.5 }}
          />
        </RadioGroup>

        {strictDisabled && (
          <Alert severity="info" sx={{ fontSize: 13 }}>
            <Trans
              i18nKey="cookieStrictness.strictDisabledNote"
              values={{ blockers: blockers.join(", ") }}
              components={{ strong: <strong /> }}
            >
              {"Strict requires no link-based auth flows. Currently active: <strong>{{blockers}}</strong>. Disable those before switching to Strict."}
            </Trans>
          </Alert>
        )}

      <SaveBar dirty={dirty} saving={saving} onSave={save} onDiscard={() => setValue(persisted)} />
    </Stack>
  );
}

// =====================================================================
// CustomDomainInstructionsDialog - DNS / TLS / cookie-domain runbook
// for pointing a friendly hostname at this install. Lifted from the
// previous standalone "Custom Domain" tab; lives in a dialog now so
// the per-mode panel stays focused on configuration, not docs.
// =====================================================================

function CustomDomainInstructionsDialog({
  open,
  onClose,
  workspaceID,
}: {
  open: boolean;
  onClose: () => void;
  workspaceID: string;
}) {
  const { t } = useTranslation();
  const Code = ({ children }: { children: React.ReactNode }) => (
    <Box
      component="code"
      sx={{
        fontFamily: "var(--font-mono)",
        bgcolor: "action.hover",
        px: 0.75,
        py: 0.25,
        borderRadius: 0.5,
        fontSize: "0.875em",
      }}
    >
      {children}
    </Box>
  );

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle sx={{ pr: 6 }}>
        {t("customDomain.title", { defaultValue: "Custom domain setup" })}
        <IconButton
          onClick={onClose}
          sx={{ position: "absolute", right: 8, top: 8 }}
          size="small"
        >
          <X size={14} strokeWidth={1.75} />
        </IconButton>
      </DialogTitle>
      <DialogContent dividers>
        <Stack spacing={2.5}>
          <Typography variant="body2" color="text.secondary">
            Bind <Code>auth.yourdomain.com</Code> so ManyRows runs same-site
            alongside your app. The mechanism is{" "}
            <strong>Cloudflare for SaaS + Custom Hostnames</strong>: customer
            hostnames terminate at Cloudflare, a Worker rewrites the{" "}
            <Code>Host</Code> header to this install's origin, and end-users
            see a clean URL with no proxy hops. The flow has a one-time
            ManyRows-side setup plus three per-customer DNS records.
          </Typography>

          <Alert severity="info" sx={{ fontSize: 13 }}>
            {t("customDomain.originRulesNote", { defaultValue: "Origin Rules (Host + SNI rewrite) are Enterprise-only. The Worker below does the same thing on Free/Paid plans for a few dollars a month." })}
          </Alert>

          {/* ---------- One-time ManyRows-side ---------- */}
          <Typography sx={{ fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.14em", fontSize: 10.5, fontWeight: 500, color: "text.disabled" }}>
            {t("customDomain.oneTimeSetupLabel", { defaultValue: "One-time setup (ManyRows side)" })}
          </Typography>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.step1", { defaultValue: "1. Cloudflare zone for ManyRows" })}
            </Typography>
            <Stack component="ul" sx={{ pl: 2.5, m: 0, gap: 0.5 }}>
              <Typography component="li" variant="body2" color="text.secondary">
                In your <Code>example.com</Code> zone, enable{" "}
                <strong>SSL/TLS → Custom Hostnames</strong> (Cloudflare for
                SaaS).
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary">
                Set <strong>Fallback Origin</strong> to a proxied DNS record
                in this zone (e.g. <Code>app.example.com</Code>). Status
                must show <Code>Active</Code>. Don't use the platform-direct
                hostname (e.g. a <Code>*.herokuapp.com</Code> URL) - it has
                to be a proxied record under the zone.
              </Typography>
            </Stack>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.step2", { defaultValue: "2. Deploy the host-rewrite Worker" })}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              <strong>Workers &amp; Pages → Create Worker → "saas-host-rewrite"</strong>.
              Paste this exact code; it rewrites <Code>Host</Code> to your
              origin so the platform router accepts the request, and forwards
              the original hostname in <Code>X-Original-Host</Code> so
              ManyRows can resolve which app the request is for.
            </Typography>
            <Box
              component="pre"
              sx={{
                fontFamily: "var(--font-mono)",
                bgcolor: "action.hover",
                p: 1.5,
                borderRadius: 1,
                fontSize: 12,
                overflowX: "auto",
                m: 0,
                whiteSpace: "pre",
              }}
            >{`export default {
  async fetch(request) {
    const url = new URL(request.url);
    const originalHost = url.hostname;

    url.hostname = "app.example.com";

    const newHeaders = new Headers(request.headers);
    newHeaders.set("Host", "app.example.com");
    newHeaders.set("X-Original-Host", originalHost);

    return fetch(url.toString(), {
      method: request.method,
      headers: newHeaders,
      body: request.body,
      redirect: "manual",
    });
  },
};`}</Box>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
              Replace <Code>app.example.com</Code> with your fallback
              origin from step 1. Pricing: 100k req/day free, then{" "}
              <Code>$5/mo</Code> Paid plan covers 10M req/mo.
            </Typography>
          </Box>

          {/* ---------- Per-customer ---------- */}
          <Typography sx={{ fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.14em", fontSize: 10.5, fontWeight: 500, color: "text.disabled", mt: 1 }}>
            {t("customDomain.perCustomerLabel", { defaultValue: "Per customer (repeat for each app)" })}
          </Typography>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.step3", { defaultValue: "3. Add the Custom Hostname in Cloudflare" })}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              Cloudflare → <Code>example.com</Code> zone → SSL/TLS → Custom
              Hostnames → <strong>Add Custom Hostname</strong>:
            </Typography>
            <Box
              component="pre"
              sx={{
                fontFamily: "var(--font-mono)",
                bgcolor: "action.hover",
                p: 1.5,
                borderRadius: 1,
                fontSize: 12,
                overflowX: "auto",
                m: 0,
                whiteSpace: "pre",
              }}
            >{`Custom Hostname:        auth.<customer>.com
Minimum TLS version:    TLS 1.2
Certificate type:       Provided by Cloudflare
Validation method:      TXT Validation
Custom origin server:   Default origin server`}</Box>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
              Submit. Cloudflare returns three values you'll hand to the
              customer: a TXT for ACME validation, a TXT for hostname
              ownership, and the CNAME target.
            </Typography>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.step4", { defaultValue: "4. Customer adds three DNS records" })}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              On <Code>&lt;customer&gt;.com</Code> - DNS provider doesn't
              have to be Cloudflare:
            </Typography>
            <Box
              component="pre"
              sx={{
                fontFamily: "var(--font-mono)",
                bgcolor: "action.hover",
                p: 1.5,
                borderRadius: 1,
                fontSize: 12,
                overflowX: "auto",
                m: 0,
                whiteSpace: "pre",
              }}
            >{`CNAME  auth                       app.example.com   (DNS only - gray cloud, NEVER proxied)
TXT    _acme-challenge.auth       <ACME value from CF>
TXT    _cf-custom-hostname.auth   <hostname ownership UUID>`}</Box>
            <Stack component="ul" sx={{ pl: 2.5, m: 0, gap: 0.5, mt: 1 }}>
              <Typography component="li" variant="body2" color="text.secondary">
                <strong>The CNAME must NOT be proxied</strong> on the
                customer's side (gray cloud / DNS-only). An orange cloud
                creates a self-loop and validation fails.
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary">
                In most DNS UIs the <Code>Name</Code> field expects just the
                subdomain part - the FQDN gets auto-appended. So{" "}
                <Code>auth</Code> not <Code>auth.customer.com</Code>.
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary">
                Once the CNAME is live, the{" "}
                <Code>_cf-custom-hostname</Code> TXT becomes redundant and
                can be removed. Leave it during initial setup.
              </Typography>
            </Stack>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.step5", { defaultValue: "5. Wait for Cloudflare to validate" })}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              On the Custom Hostnames page, the row flips:
            </Typography>
            <Stack component="ul" sx={{ pl: 2.5, m: 0, gap: 0.5 }}>
              <Typography component="li" variant="body2" color="text.secondary">
                <strong>Hostname status</strong>: Pending Validation (TXT)
                → <Code>Active</Code> (a few minutes after DNS propagates).
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary">
                <strong>Certificate status</strong>: Pending Validation →{" "}
                <Code>Active</Code> (5–30 min on first issuance - Google
                Trust Services is the CA on non-Enterprise plans).
              </Typography>
            </Stack>
            <Alert severity="warning" sx={{ fontSize: 13, mt: 1.5 }}>
              <strong>Cert stuck Pending after 30+ minutes?</strong>
              <Stack component="ol" sx={{ pl: 2.5, m: 0, mt: 1, gap: 0.5 }}>
                <Typography component="li" variant="body2">
                  Verify the TXT value:{" "}
                  <Code>dig +short TXT _acme-challenge.auth.&lt;customer&gt;.com</Code>
                  . Capital-I vs lowercase-l mistypes are the most common
                  cause.
                </Typography>
                <Typography component="li" variant="body2">
                  <strong>Toggle the validation method to reset the ACME flow.</strong>{" "}
                  Click <strong>Edit</strong> on the row → switch
                  Certificate validation method from <Code>TXT</Code> to{" "}
                  <Code>HTTP</Code>, save → switch back to <Code>TXT</Code>,
                  save. This kicks Cloudflare into restarting the
                  cert-issuance state machine - useful when an earlier
                  proxied-CNAME mistake leaves the ACME flow stuck even
                  after the CNAME is fixed.
                </Typography>
                <Typography component="li" variant="body2">
                  If still stuck, delete and re-add the custom hostname.
                  Cloudflare hands out fresh tokens; update DNS to match.
                </Typography>
              </Stack>
            </Alert>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.step6", { defaultValue: "6. Bind the Worker route" })}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
              <strong>Workers &amp; Pages → saas-host-rewrite → Domains
              &amp; Routes → Add → Route</strong>:
            </Typography>
            <Box
              component="pre"
              sx={{
                fontFamily: "var(--font-mono)",
                bgcolor: "action.hover",
                p: 1.5,
                borderRadius: 1,
                fontSize: 12,
                overflowX: "auto",
                m: 0,
                whiteSpace: "pre",
              }}
            >{`Zone:           example.com
Route:          auth.<customer>.com/*
Failure mode:   Fail closed (block)`}</Box>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.step7", { defaultValue: "7. Smoke test" })}
            </Typography>
            <Box
              component="pre"
              sx={{
                fontFamily: "var(--font-mono)",
                bgcolor: "action.hover",
                p: 1.5,
                borderRadius: 1,
                fontSize: 12,
                overflowX: "auto",
                m: 0,
                whiteSpace: "pre",
              }}
            >{`curl -i https://auth.<customer>.com/health
curl -i https://app.example.com/health     # should match`}</Box>
            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
              When responses match, the pipe is wired. ManyRows sees{" "}
              <Code>Host: app.example.com</Code> (rewritten) and{" "}
              <Code>X-Original-Host: auth.&lt;customer&gt;.com</Code> (added
              by the Worker), and uses the latter to resolve the app.
            </Typography>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.step8", { defaultValue: "8. Tell ManyRows the hostname" })}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Save <Code>auth.&lt;customer&gt;.com</Code> in the{" "}
              <strong>Cookie domain</strong> field on the previous screen
              (or set <Code>MANYROWS_BASE_URL</Code> on a self-hosted
              install). The Go middleware uses this to scope session
              cookies + JWT <Code>iss</Code> claims correctly.
            </Typography>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.cookieSettingsHeading", { defaultValue: "Cookie domain settings (recommended)" })}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              For multi-env safety, ManyRows issues <strong>host-only</strong>{" "}
              session cookies on <Code>auth.&lt;customer&gt;.com</Code>{" "}
              (no <Code>Domain</Code> attribute) - they don't bleed into
              sibling subdomains like <Code>staging.&lt;customer&gt;.com</Code>.
              The customer's frontend at <Code>&lt;customer&gt;.com</Code>{" "}
              calls <Code>auth.&lt;customer&gt;.com/api/token</Code> with{" "}
              <Code>credentials: "include"</Code> to mint short-lived JWTs
              for their own backend, which validates them against{" "}
              <RouterLink
                to={`/app/workspace/${workspaceID}/settings`}
                style={{ color: "inherit", textDecoration: "underline" }}
              >
                ManyRows' JWKS
              </RouterLink>
              . Stateless on both sides, no shared signing key.
            </Typography>
          </Box>

          <Box>
            <Typography sx={{ fontSize: 13, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
              {t("customDomain.gotchasHeading", { defaultValue: "Common gotchas" })}
            </Typography>
            <Stack component="ul" sx={{ pl: 2.5, m: 0, gap: 0.5 }}>
              <Typography component="li" variant="body2" color="text.secondary">
                <strong>Customer's CNAME proxied (orange cloud)</strong> →
                self-loop, validation fails. Must be DNS-only / gray cloud.
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary">
                <strong>Don't <Code>heroku domains:add</Code> per customer</strong>
                {" "}(or equivalent on Render/Fly/etc.). The Worker rewrites
                Host before the request reaches your platform router; the
                platform only needs to know about your fallback origin.
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary">
                <strong>Fallback origin must be in your zone</strong> - a
                proxied DNS record under <Code>example.com</Code>, not the
                platform's direct URL.
              </Typography>
              <Typography component="li" variant="body2" color="text.secondary">
                <strong>Avoid parent-scoped cookies</strong>{" "}
                (<Code>Domain=&lt;customer&gt;.com</Code>). They leak across
                env subdomains (prod ↔ staging). Stick with host-only.
              </Typography>
            </Stack>
          </Box>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{t("common.close", { defaultValue: "Close" })}</Button>
      </DialogActions>
    </Dialog>
  );
}
