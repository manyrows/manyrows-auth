import * as React from "react";
import type { App, Product, Workspace } from "../core.ts";
import { appDisplayName, appTypeLabel } from "../core.ts";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Box,
  Drawer,
  Paper,
  Stack,
  Typography,
  IconButton,
  Tooltip,
  Button,
  Chip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import { useTranslation } from "react-i18next";
import {
  ArrowLeft,
  Home,
  Folder,
  Code,
  ChevronDown,
  Menu as MenuIcon,
} from "lucide-react";

type AppRow = {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
};
import ProductSideMenu from "./ProductSideMenu.tsx";
import AppSideMenu from "./AppSideMenu.tsx";
import Loader from "../Loader.tsx";

const ProductSettings = React.lazy(() => import("./ProductSettings.tsx"));
const Roles = React.lazy(() => import("./Roles.tsx"));
const Permissions = React.lazy(() => import("./Permissions.tsx"));
const AppUsers = React.lazy(() => import("./AppUsers.tsx"));
const Apps = React.lazy(() => import("./Apps.tsx"));
const Features = React.lazy(() => import("./Features.tsx"));
const ConfigKeys = React.lazy(() => import("./ConfigKeys.tsx"));
const AppDetail = React.lazy(() => import("./AppDetail.tsx"));
const AppAuthMethods = React.lazy(() => import("./AppAuthMethods.tsx"));
const AppSecurity = React.lazy(() => import("./AppSecurity.tsx"));
const AppDiff = React.lazy(() => import("./AppDiff.tsx"));
const AppQuickStart = React.lazy(() => import("./AppQuickStart.tsx"));
const AppInsights = React.lazy(() => import("./AppInsights.tsx"));
const Sessions = React.lazy(() => import("../workspace/Sessions.tsx"));
const AuthLogs = React.lazy(() => import("../workspace/AuthLogs.tsx"));
const ApiKeys = React.lazy(() => import("../workspace/ApiKeys.tsx"));
const AppCorsOrigins = React.lazy(() => import("./AppCorsOrigins.tsx"));
const AppIPAllowlist = React.lazy(() => import("./AppIPAllowlist.tsx"));
const Webhooks = React.lazy(() => import("./Webhooks.tsx"));
const Branding = React.lazy(() => import("./Branding.tsx"));

interface Props {
  workspace: Workspace;
  page: string;
  productId: string;
  appId?: string;
  appPage?: string;
}

async function fetchProduct(workspaceId: string, productId: string): Promise<Product> {
  // keep this path aligned with your backend
  return axios.get(`/admin/workspace/${workspaceId}/products/${productId}`).then((r) => r.data);
}


export default function ProductHome(props: Props) {
  const { workspace, page, productId, appId, appPage } = props;
  const nav = useNavigate();
  const { t } = useTranslation();

  const [project, setProduct] = React.useState<Product | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [loadErr, setLoadErr] = React.useState<string | null>(null);
  const [appName, setAppName] = React.useState("");
  const [appType, setAppType] = React.useState("");
  const [appAuthDomain, setAppAuthDomain] = React.useState("");
  const [apps, setApps] = React.useState<AppRow[]>([]);
  const [switcherAnchor, setSwitcherAnchor] = React.useState<null | HTMLElement>(null);
  const [mobileNavOpen, setMobileNavOpen] = React.useState(false);

  // Close drawer when route changes
  React.useEffect(() => {
    setMobileNavOpen(false);
  }, [page, appId, appPage]);

  const goToWorkspace = () => {
    nav(`/app/workspace/${workspace.id}`);
  };

  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    setLoadErr(null);

    fetchProduct(workspace.id, productId)
      .then((p) => {
        if (!alive) return;
        setProduct(p);
        setLoading(false);
      })
      .catch((e) => {
        if (!alive) return;
        setProduct(null);
        setLoading(false);
        setLoadErr(extractApiError(e, t("projectHome.failedToLoad")));
      });

    return () => {
      alive = false;
    };
  }, [workspace.id, productId]);

  React.useEffect(() => {
    if (!productId) return;
    let alive = true;
    const appsURL = `/admin/workspace/${workspace.id}/products/${productId}/apps`;
    axios.get(appsURL).catch(() => ({ data: { apps: [] } })).then((allAppsRes) => {
      if (!alive) return;
      const rows: AppRow[] = ((allAppsRes.data?.apps || []) as App[]).map((ap) => ({
        id: ap.id,
        name: appDisplayName(ap),
        type: ap.type || "",
        enabled: !!ap.enabled,
      }));
      setApps(rows);
    });
    return () => { alive = false; };
  }, [workspace.id, productId]);

  React.useEffect(() => {
    if (!appId || !productId) {
      setAppName("");
      setAppType("");
      setAppAuthDomain("");
      return;
    }
    let alive = true;
    const appsURL = `/admin/workspace/${workspace.id}/products/${productId}/apps`;
    Promise.all([
      axios.get(`/admin/workspace/${workspace.id}/products/${productId}/apps/${appId}/`),
      axios.get(appsURL).catch(() => ({ data: { apps: [] } })),
    ]).then(([appRes, allAppsRes]) => {
      if (!alive) return;
      const a = appRes.data;
      // apps.name is gone server-side; display name is computed from
      // the parent product + env type. appDisplayName() does the
      // composition so the switcher's header title matches the rest
      // of the admin UI ("Drum Kingdom (Staging)" etc.).
      setAppName(a ? appDisplayName(a) : "");
      setAppType(a?.type || "");
      setAppAuthDomain(a?.authDomain || "");

      const rows: AppRow[] = ((allAppsRes.data?.apps || []) as App[]).map((ap) => ({
        id: ap.id,
        name: appDisplayName(ap),
        type: ap.type || "",
        enabled: !!ap.enabled,
      }));
      rows.sort((x, y) => x.name.localeCompare(y.name));
      setApps(rows);
    }).catch(() => {
      if (!alive) return;
      setAppName("");
      setAppType("");
      setAppAuthDomain("");
      setApps([]);
    });
    return () => { alive = false; };
  }, [workspace.id, productId, appId]);

  if (loading) return <Loader />;

  // If fetch failed / project missing, keep it simple (still let them go back)
  if (!project) {
    return (
      <Box sx={{ p: 2 }}>
        <Paper variant="outlined" sx={{ overflow: "hidden" }}>
          <Box
            sx={{
              px: 2,
              py: 1.25,
              borderBottom: "1px solid",
              borderColor: "divider",
            }}
          >
            <Stack direction="row" spacing={1.5} alignItems="center">
              <Tooltip title={t("projectHome.backToWorkspace")}>
                    <span>
                <IconButton size="small" onClick={goToWorkspace}>
                  <ArrowLeft size={14} strokeWidth={1.75} />
                </IconButton>
                    </span>
              </Tooltip>

              <Box component="span" sx={{ color: "text.secondary", display: "inline-flex", alignItems: "center" }}><Folder size={18} strokeWidth={1.75} /></Box>

              <Box sx={{ minWidth: 0, flex: 1 }}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography sx={{ fontSize: 15, fontWeight: 600 }}>
                    {t("projectHome.project")}
                  </Typography>
                  <Typography sx={{ fontSize: 13, color: "text.disabled" }}>
                    {workspace.name}
                  </Typography>
                </Stack>
              </Box>
            </Stack>
          </Box>

          <Box sx={{ p: { xs: 2, sm: 4 }, textAlign: "center", maxWidth: 480, mx: "auto" }}>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 1, color: "error.main" }}>
              {t("projectHome.unableToLoad")}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
              {loadErr || t("projectHome.notFoundOrNoAccess")}
            </Typography>
            <Button
              variant="contained"
              startIcon={<Home size={14} strokeWidth={1.75} />}
              onClick={goToWorkspace}
              disableElevation
              sx={{ borderRadius: 2, textTransform: "none" }}
            >
              {t("projectHome.backToWorkspace")}
            </Button>
          </Box>
        </Paper>
      </Box>
    );
  }

  const sideMenu =
    page === "appDetail" && appId ? (
      <AppSideMenu
        projectBasePath={`/app/workspace/${workspace.id}/products/${productId}`}
        appBasePath={`/app/workspace/${workspace.id}/products/${productId}/apps/${appId}`}
        value={appPage || "appDetail"}
      />
    ) : (
      <ProductSideMenu
        value={page}
        basePath={`/app/workspace/${workspace.id}/products/${productId}`}
        workspaceBasePath={`/app/workspace/${workspace.id}`}
      />
    );

  return (
    <Box
      sx={{
        display: { xs: "block", md: "grid" },
        gridTemplateColumns: { md: "200px 1fr" },
        minHeight: { md: "calc(100vh - 52px)" },
      }}
    >
      {/* Desktop sidebar - md+ only */}
      <Box sx={{ display: { xs: "none", md: "block" } }}>{sideMenu}</Box>

      {/* Mobile drawer */}
      <Drawer
        open={mobileNavOpen}
        onClose={() => setMobileNavOpen(false)}
        sx={{ display: { md: "none" } }}
        PaperProps={{ sx: { width: 260 } }}
      >
        {sideMenu}
      </Drawer>

      {/* Main */}
      <Box
        sx={{
          bgcolor: "background.paper",
          overflowY: { md: "auto" },
          maxHeight: { md: "calc(100vh - 52px)" },
        }}
      >
        {/* Mobile hamburger trigger */}
        <Box
          sx={{
            display: { xs: "flex", md: "none" },
            alignItems: "center",
            gap: 1,
            px: 1.5,
            py: 1,
            borderBottom: "1px solid",
            borderColor: "divider",
            bgcolor: "background.paper",
          }}
        >
          <IconButton
            size="small"
            onClick={() => setMobileNavOpen(true)}
            aria-label={t("projectHome.openNavigation")}
          >
            <MenuIcon size={16} strokeWidth={1.75} />
          </IconButton>
          <Typography
            sx={{
              fontFamily: "var(--font-mono)",
              textTransform: "uppercase",
              letterSpacing: "0.16em",
              fontSize: 10,
              fontWeight: 500,
              color: "text.disabled",
            }}
          >
            {t("projectHome.menu")}
          </Typography>
        </Box>

        <Box sx={{ p: { xs: 2, sm: 3 } }}>
            {/* Editorial app header - mono overline, Fraunces serif
                name with env pip, and a small mono meta line for app id
                + auth domain. The title itself isn't a button anymore;
                a discrete "switch" link to its right opens the
                project-wide app switcher menu. */}
            {page === "appDetail" && appId && appName && (
              <Box sx={{ mb: 3 }}>
                <Typography
                  sx={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 1,
                    fontFamily: "var(--font-mono)",
                    textTransform: "uppercase",
                    letterSpacing: "0.18em",
                    fontSize: 10.5,
                    fontWeight: 500,
                    color: "text.disabled",
                    mb: 1,
                  }}
                >
                  <Box component="span" sx={{ width: 4, height: 4, borderRadius: "50%", bgcolor: "primary.main" }} />
                  {t("projectHome.appEyebrow")}
                </Typography>
                <Stack direction="row" spacing={1.5} alignItems="center" sx={{ minWidth: 0 }}>
                  <Typography
                    sx={{
                      fontFamily: "var(--font-serif)",
                      fontSize: 30,
                      fontWeight: 500,
                      letterSpacing: "-0.025em",
                      lineHeight: 1.2,
                      fontOpticalSizing: "auto",
                      color: "text.primary",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      minWidth: 0,
                      pb: "2px",
                    }}
                  >
                    {appName}
                  </Typography>
                  {appType && (
                    <Chip
                      size="small"
                      label={appTypeLabel({ type: appType })}
                      variant="outlined"
                      sx={{
                        height: 22,
                        fontSize: 10.5,
                        fontWeight: 600,
                        letterSpacing: "0.08em",
                        fontFamily: "var(--font-mono)",
                        textTransform: "uppercase",
                        flexShrink: 0,
                        ...(appType === "prod" && { borderColor: "error.main", color: "error.main" }),
                        ...(appType === "staging" && { borderColor: "warning.main", color: "warning.main" }),
                        ...(appType === "dev" && { borderColor: "success.main", color: "success.main" }),
                      }}
                    />
                  )}
                  <Box
                    component="button"
                    onClick={(e: React.MouseEvent<HTMLButtonElement>) => setSwitcherAnchor(e.currentTarget)}
                    sx={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 0.5,
                      px: 1,
                      height: 24,
                      border: "none",
                      borderRadius: 1,
                      bgcolor: "transparent",
                      color: "text.disabled",
                      fontFamily: "inherit",
                      fontSize: 12,
                      fontWeight: 500,
                      cursor: "pointer",
                      transition: "background-color 120ms ease, color 120ms ease",
                      "&:hover": { bgcolor: "action.hover", color: "text.primary" },
                    }}
                  >
                    {t("projectHome.switch")}
                    <ChevronDown size={10} strokeWidth={1.75} />
                  </Box>
                </Stack>
                <Stack
                  direction="row"
                  spacing={2}
                  alignItems="center"
                  sx={{
                    mt: 1.25,
                    fontFamily: "var(--font-mono)",
                    fontSize: 11.5,
                    color: "text.disabled",
                  }}
                >
                  <Box component="span">
                    <Box component="span" sx={{ color: "text.disabled" }}>{t("projectHome.appId")}</Box>
                    <Box component="span" sx={{ color: "text.secondary", ml: 1 }}>{appId}</Box>
                  </Box>
                  {appAuthDomain && (
                    <>
                      <Box component="span" sx={{ opacity: 0.4 }}>·</Box>
                      <Box component="span">
                        <Box component="span" sx={{ color: "text.disabled" }}>{t("projectHome.authDomain")}</Box>
                        <Box component="span" sx={{ color: "text.secondary", ml: 1 }}>{appAuthDomain}</Box>
                      </Box>
                    </>
                  )}
                </Stack>
                <Menu
                  anchorEl={switcherAnchor}
                  open={Boolean(switcherAnchor)}
                  onClose={() => setSwitcherAnchor(null)}
                  slotProps={{ paper: { sx: { minWidth: 280, maxHeight: 320 } } }}
                >
                  {apps.map((ap) => (
                    <MenuItem
                      key={ap.id}
                      selected={ap.id === appId}
                      onClick={() => {
                        setSwitcherAnchor(null);
                        if (ap.id !== appId) {
                          nav(`/app/workspace/${workspace.id}/products/${productId}/apps/${ap.id}/${appPage || ""}`);
                        }
                      }}
                    >
                      <ListItemIcon>
                        <Box component="span" sx={{ display: "inline-flex", alignItems: "center", color: ap.enabled ? "primary.main" : "text.disabled" }}>
                          <Code size={16} strokeWidth={1.75} />
                        </Box>
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Stack direction="row" spacing={1} alignItems="center" sx={{ minWidth: 0 }}>
                            <Typography
                              sx={{
                                fontSize: 14,
                                fontWeight: 500,
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                                minWidth: 0,
                              }}
                            >
                              {ap.name || t("apps.untitledApp", { defaultValue: "Untitled App" })}
                            </Typography>
                            {ap.type && (
                              <Chip
                                size="small"
                                label={appTypeLabel({ type: ap.type })}
                                variant="outlined"
                                sx={{
                                  height: 20,
                                  fontSize: 10.5,
                                  fontWeight: 600,
                                  flexShrink: 0,
                                  ...(ap.type === "prod" && { borderColor: "error.main", color: "error.main" }),
                                  ...(ap.type === "staging" && { borderColor: "warning.main", color: "warning.main" }),
                                  ...(ap.type === "dev" && { borderColor: "success.main", color: "success.main" }),
                                }}
                              />
                            )}
                          </Stack>
                        }
                      />
                    </MenuItem>
                  ))}
                </Menu>
                <Box sx={{ borderBottom: "1px solid", borderColor: "divider", mt: 2 }} />
              </Box>
            )}

            <React.Suspense fallback={<Loader />}>
              {page === "apps" ? (
                <Apps project={project} workspace={workspace} />
              ) : page === "features" ? (
                <Features project={project} workspace={workspace} />
              ) : page === "configKeys" ? (
                <ConfigKeys project={project} workspace={workspace} />
              ) : page === "roles" ? (
                <Roles project={project} workspace={workspace} />
              ) : page === "members" ? (
                <AppUsers project={project} />
              ) : page === "permissions" ? (
                <Permissions project={project} workspace={workspace} />
              ) : page === "branding" ? (
                <Branding project={project} workspace={workspace} />
              ) : page === "settings" ? (
                <ProductSettings project={project} />
              ) : page === "appDetail" && appId && appPage === "auth-methods" ? (
                <AppAuthMethods project={project} workspace={workspace} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "security" ? (
                <AppSecurity project={project} workspace={workspace} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "features" ? (
                <Features project={project} workspace={workspace} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "config" ? (
                <ConfigKeys project={project} workspace={workspace} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "members" ? (
                <AppUsers project={project} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "quick-start" ? (
                <AppQuickStart project={project} workspace={workspace} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "insights" ? (
                <AppInsights project={project} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "sessions" ? (
                <Sessions workspaceId={workspace.id} appId={appId} initialEmail={new URLSearchParams(window.location.search).get("email") || undefined} />
              ) : page === "appDetail" && appId && appPage === "auth-logs" ? (
                <AuthLogs workspaceId={workspace.id} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "api-keys" ? (
                <ApiKeys workspaceId={workspace.id} appId={appId} />
              ) : page === "appDetail" && appId && appPage === "cors" ? (
                <AppCorsOrigins workspaceId={workspace.id} productId={project.id} appId={appId} inline />
              ) : page === "appDetail" && appId && appPage === "ip-allowlist" ? (
                <AppIPAllowlist workspaceId={workspace.id} productId={project.id} appId={appId} inline />
              ) : page === "appDetail" && appId && appPage === "webhooks" ? (
                <Webhooks project={project} workspace={workspace} appId={appId} />
              ) : page === "appDetail" && appId ? (
                <AppDetail project={project} workspace={workspace} appId={appId} onAppUpdated={(a) => { setAppName(a.name); setAppType(a.type || ""); }} />
              ) : page === "appDiff" ? (
                <AppDiff project={project} workspace={workspace} />
              ) : (
                <></>
              )}
            </React.Suspense>
        </Box>
      </Box>
    </Box>
  );
}
