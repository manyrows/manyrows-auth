import {
  Box,
  Drawer,
  IconButton,
  Typography,
  Button,
} from "@mui/material";
import { Lock, Home, Menu as MenuIcon } from "lucide-react";
import * as React from "react";
import type { Workspace } from "../core.ts";
import { useNavigate } from "react-router-dom";
import { useTranslation, Trans } from "react-i18next";
import Loader from "../Loader.tsx";
import WorkspaceSideMenu from "./WorkspaceSideMenu.tsx";

const WorkspaceSummary = React.lazy(() => import("./WorkspaceSummary.tsx"));
const WorkspaceSettings = React.lazy(() => import("./WorkspaceSettings.tsx"));
const WorkspaceUsers = React.lazy(() => import("./WorkspaceUsers.tsx"));
const UserPools = React.lazy(() => import("./UserPools.tsx"));
const PoolDetail = React.lazy(() => import("./PoolDetail.tsx"));
const SsoPage = React.lazy(() => import("./SsoPage.tsx"));
const Team = React.lazy(() => import("./Team.tsx"));
const EmailSettings = React.lazy(() => import("./EmailSettings.tsx"));
const SigningKeysPage = React.lazy(() => import("./SigningKeysPage.tsx"));
const CookieDomainPage = React.lazy(() => import("./CookieDomainPage.tsx"));

const tc = { code: <code />, b: <b />, strong: <strong /> };

interface WorkspaceHomeProps {
  workspace: Workspace;
  page: string;
  poolId?: string;
}

function isPrivilegedWorkspaceRole(role?: string): boolean {
  const r = (role || "").toLowerCase();
  return r === "owner" || r === "admin";
}

export default function WorkspaceHome({ workspace, page, poolId }: WorkspaceHomeProps) {
  const nav = useNavigate();
  const { t } = useTranslation();

  const role = workspace?.role || "";
  const canAccess = isPrivilegedWorkspaceRole(role);

  const [mobileNavOpen, setMobileNavOpen] = React.useState(false);

  // Close drawer when route changes
  React.useEffect(() => {
    setMobileNavOpen(false);
  }, [page]);

  const goBackToWorkspaces = () => {
    nav("/app");
  };

  // The side menu's "Summary" item highlights when we're on the
  // bare workspace URL (page === "home" or the legacy "projects"
  // alias). When we're inside a pool detail page, keep "User pools"
  // highlighted so the user knows where they came from.
  const sideMenuValue = poolId ? "userPools" : (page === "projects" ? "home" : page);
  const basePath = `/app/workspace/${workspace.id}`;

  if (!canAccess) {
    return (
      <Box sx={{ p: { xs: 3, sm: 5 }, textAlign: "center", maxWidth: 480, mx: "auto" }}>
        <Box
          sx={{
            width: 64,
            height: 64,
            borderRadius: 3,
            bgcolor: "action.selected",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            mx: "auto",
            mb: 2,
          }}
        >
          <Box component="span" sx={{ color: "primary.main", display: "inline-flex" }}><Lock size={36} strokeWidth={1.5} /></Box>
        </Box>

        <Typography sx={{ fontSize: 17, fontWeight: 600, letterSpacing: "-0.005em", mb: 1 }}>
          {t("workspaceHome.accessRestricted")}
        </Typography>
        <Typography
          variant="body2"
          color="text.secondary"
          sx={{ mb: 3 }}
        ><Trans i18nKey="workspaceHome.accessRestrictedDesc" components={tc} /></Typography>

        <Button
          variant="contained"
          startIcon={<Home size={14} strokeWidth={1.75} />}
          onClick={goBackToWorkspaces}
          disableElevation
          sx={{ borderRadius: 2, textTransform: "none" }}
        >
          {t("workspaceHome.backToHome")}
        </Button>
      </Box>
    );
  }

  const sideMenu = <WorkspaceSideMenu value={sideMenuValue} basePath={basePath} />;

  return (
    <Box
      sx={{
        display: { xs: "block", md: "grid" },
        gridTemplateColumns: { md: "240px 1fr" },
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
            aria-label={t("workspaceHome.openNavigation")}
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
            {t("workspaceHome.menu")}
          </Typography>
        </Box>

        <Box sx={{ p: { xs: 2, sm: 3 } }}>
          <React.Suspense fallback={<Loader />}>
            {page === "home" || page === "projects" ? (
              <WorkspaceSummary workspace={workspace} />
            ) : page === "settings" ? (
              <WorkspaceSettings workspace={workspace} />
            ) : page === "emailSettings" ? (
              <EmailSettings workspaceId={workspace.id} />
            ) : page === "team" ? (
              <Team workspace={workspace} />
            ) : page === "users" ? (
              <WorkspaceUsers workspace={workspace} />
            ) : page === "userPools" ? (
              <UserPools workspace={workspace} />
            ) : page === "sso" ? (
              <SsoPage />
            ) : page === "signingKeys" ? (
              <SigningKeysPage />
            ) : page === "cookieDomain" ? (
              <CookieDomainPage workspace={workspace} />
            ) : poolId && (page === "overview" || page === "fields" || page === "userFields" || page === "poolUsers") ? (
              <PoolDetail
                workspace={workspace}
                poolId={poolId}
                tab={
                  page === "fields" || page === "userFields"
                    ? "fields"
                    : page === "poolUsers"
                      ? "users"
                      : "overview"
                }
              />
            ) : (
              <></>
            )}
          </React.Suspense>
        </Box>
      </Box>
    </Box>
  );
}

