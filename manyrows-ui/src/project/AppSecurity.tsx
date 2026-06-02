import * as React from "react";
import axios from "axios";
import type { Project, Workspace } from "../core.ts";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import { Box, Tab, Tabs } from "@mui/material";
import Loader from "../Loader.tsx";
import PageHeader from "../components/PageHeader.tsx";
import { errText } from "./AppAuthMethods.tsx";
import type { App } from "./AppAuthMethods.tsx";
import AppCorsOrigins from "./AppCorsOrigins.tsx";
import AppIPAllowlist from "./AppIPAllowlist.tsx";
import AppPasswordPolicyCard from "./AppPasswordPolicyCard.tsx";
import AppDomainPoolTab from "./AppDomainPoolTab.tsx";
import { SessionTransportTab, SessionLifetimeTab } from "./AppSessionsCard.tsx";

// Security tab - session transport / lifetime, CORS, IP allowlist,
// password policy. Pulled out of "Auth Settings" so admins find the
// per-app integration security knobs in one place. New security-
// adjacent surfaces (e.g. outbound webhook signing keys) can mount
// as additional tabs here without crowding the auth-method screen.
interface Props {
  project: Project;
  workspace: Workspace;
  appId: string;
}

export default function AppSecurity({ project, workspace, appId }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const [loading, setLoading] = React.useState(true);
  const [app, setApp] = React.useState<App | null>(null);
  const [tab, setTab] = React.useState(0);

  const appsBaseURL = `/admin/workspace/${project.workspaceId}/projects/${project.id}/apps`;

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    axios
      .get<App>(`${appsBaseURL}/${appId}/`)
      .then((res) => {
        if (!alive) return;
        setApp(res.data);
        setLoading(false);
      })
      .catch((e) => {
        if (!alive) return;
        setLoading(false);
        enqueueSnackbar(errText(e), { variant: "error" });
      });
    return () => {
      alive = false;
    };
  }, [appId, appsBaseURL, enqueueSnackbar]);

  if (loading) return <Loader />;
  if (!app) return null;

  const cardURL = `${appsBaseURL}/${app.id}`;
  const onSaved = (updated: App) => setApp(updated);
  const onError = (e: unknown) => enqueueSnackbar(errText(e), { variant: "error" });
  const onSuccess = () => enqueueSnackbar(t("apps.appUpdated"), { variant: "success" });

  // The Sessions tab consolidates the cookie-domain config and the
  // custom-domain setup instructions into one Transport pane.
  return (
    <Box>
      <PageHeader title={t("app.nav.security", { defaultValue: "Auth settings" })} mb={2} />

      <Box sx={{ borderBottom: 1, borderColor: "divider", mb: 2 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="scrollable" scrollButtons="auto">
          <Tab label={t("appSecurity.tab.domainPool", { defaultValue: "Domain & user pool" })} />
          <Tab label={t("appSecurity.tab.sessionTransport", { defaultValue: "Session transport" })} />
          <Tab label={t("appSecurity.tab.sessionLifetime", { defaultValue: "Session lifetime" })} />
          <Tab label={t("appSecurity.tab.cors", { defaultValue: "CORS" })} />
          <Tab label={t("appSecurity.tab.ipAllowlist", { defaultValue: "IP allowlist" })} />
          <Tab label={t("appSecurity.tab.passwords", { defaultValue: "Passwords" })} />
        </Tabs>
      </Box>

      {tab === 0 && (
        <AppDomainPoolTab
          app={app}
          cardURL={cardURL}
          workspaceId={workspace.id}
          onSaved={onSaved}
          onSuccess={onSuccess}
          onError={onError}
        />
      )}
      {tab === 1 && (
        <SessionTransportTab
          app={app}
          cardURL={cardURL}
          workspaceCookieDomain={workspace.cookieDomain}
          workspaceID={workspace.id}
          onSaved={onSaved}
          onSuccess={onSuccess}
          onError={onError}
        />
      )}
      {tab === 2 && (
        <SessionLifetimeTab
          app={app}
          cardURL={cardURL}
          workspaceCookieDomain={workspace.cookieDomain}
          workspaceID={workspace.id}
          onSaved={onSaved}
          onSuccess={onSuccess}
          onError={onError}
        />
      )}
      {tab === 3 && (
        <AppCorsOrigins
          workspaceId={project.workspaceId}
          projectId={project.id}
          appId={app.id}
          inline
        />
      )}
      {tab === 4 && (
        <AppIPAllowlist
          workspaceId={project.workspaceId}
          projectId={project.id}
          appId={app.id}
          inline
        />
      )}
      {tab === 5 && (
        <AppPasswordPolicyCard
          app={app}
          cardURL={cardURL}
          onSaved={onSaved}
          onSuccess={onSuccess}
          onError={onError}
        />
      )}
    </Box>
  );
}

