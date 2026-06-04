import * as React from "react";
import {
  Box,
  Chip,
  Collapse,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Typography,
} from "@mui/material";
import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";

import {
  ArrowLeft,
  ChevronDown,
  Settings,
  IdCard,
  Layers,
  ShieldCheck,
  ArrowLeftRight,
  Palette,
  Sparkles,
  History,
  LogIn,
  Key,
  Lock,
  Users,
  Flag,
  SlidersHorizontal,
  Bell,
  KeyRound,
  LineChart,
} from "lucide-react";

import { appTypeLabel } from "../core.ts";

interface AppContext {
  appType?: string; // "dev" | "staging" | "prod"
  appBasePath: string; // e.g. "/app/workspace/123/projects/456/apps/789"
  appPage: string; // current sub-page (e.g. "auth-methods")
  onOpenSwitcher?: (anchor: HTMLElement) => void;
}

interface Props {
  value: string;
  basePath: string; // e.g. "/app/workspace/123/projects/456"
  workspaceBasePath: string; // e.g. "/app/workspace/123"
  app?: AppContext;
}

const itemSx = {
  px: 1.25,
  py: 0.35,
  minHeight: 28,
  borderRadius: 1,
};

const iconSx = {
  minWidth: 24,
  color: "text.secondary" as const,
  display: "flex",
  alignItems: "center",
};

const ICON_SIZE = 14;
const ICON_STROKE = 1.75;

export default function ProjectSideMenu({ value, basePath, workspaceBasePath, app }: Props) {
  const { t } = useTranslation();

  // When we're truly inside an app (appPage set), "Apps" is the active
  // project row. When the sub-tree is only sticky (user popped out to
  // Roles/Permissions/etc.) the real project page should highlight
  // instead.
  const insideApp = !!app && !!app.appPage;
  const effectiveValue = insideApp ? "apps" : value;

  return (
    <Box
      sx={{
        p: 1,
        borderRight: { md: "1px solid rgba(13, 10, 8, 0.06)" },
        bgcolor: { md: "background.default" },
        height: { md: "calc(100vh - 52px)" },
        position: { md: "sticky" },
        top: { md: 52 },
        overflowY: { md: "auto" },
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": { bgcolor: "rgba(13,10,8,0.10)", borderRadius: 3 },
      }}
    >
      <List disablePadding sx={{ display: "grid", gap: 0, mb: 0.5 }}>
        <ListItemButton
          component={Link}
          to={workspaceBasePath}
          sx={{ ...itemSx, color: "text.secondary" }}
        >
          <ListItemIcon sx={iconSx}>
            <ArrowLeft size={ICON_SIZE} strokeWidth={ICON_STROKE} />
          </ListItemIcon>
          <ListItemText
            primary={t("project.nav.backToWorkspace", { defaultValue: "Back to Workspace" })}
            primaryTypographyProps={{ fontSize: 12.5, fontWeight: 500 }}
          />
        </ListItemButton>
      </List>

      <Section>
        <NavItem
          label={t("project.nav.settings", { defaultValue: "Project Settings" })}
          value="settings"
          icon={<Settings size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={effectiveValue}
          basePath={basePath}
        />

        <NavItem
          label={t("project.nav.apps")}
          value="apps"
          icon={<Layers size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={effectiveValue}
          basePath={basePath}
          trailing={
            app ? (
              <Box
                component="span"
                sx={{
                  display: "inline-flex",
                  alignItems: "center",
                  color: "text.disabled",
                  ml: 0.5,
                  flexShrink: 0,
                }}
              >
                <ChevronDown size={12} strokeWidth={ICON_STROKE} />
              </Box>
            ) : undefined
          }
        />

        {app && <AppSubNav app={app} t={t} basePath={basePath} selectedValue={effectiveValue} />}
      </Section>
    </Box>
  );
}

// Sub-tree under "Apps" when an app is open. Indented with a thin left rail
// so the parent/child relationship reads at a glance.
function AppSubNav({
  app,
  t,
  basePath,
  selectedValue,
}: {
  app: AppContext;
  t: (k: string, o?: Record<string, unknown>) => string;
  basePath: string;
  selectedValue: string;
}) {
  const { appType, appBasePath, appPage, onOpenSwitcher } = app;

  // Collapsible group state. Data starts collapsed so opening an app lands on a
  // compact tree; Auth + Configuration stay open. Session-only — resets on
  // reload, and a manual toggle sticks for the rest of the session.
  const [collapsed, setCollapsed] = React.useState<Set<string>>(
    () =>
      new Set([
        t("app.navGroup.data", { defaultValue: "Data" }),
      ]),
  );
  const toggleGroup = (label: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(label)) next.delete(label);
      else next.add(label);
      return next;
    });

  // Grouped so the per-environment surface reads as Data / Auth / Config rather
  // than one flat list — Data leads, and the auth groups sit together so they're
  // easy to ignore when an environment isn't really using auth.
  // selectedOverride lets a project-scoped row (e.g. Branding) live inside an
  // app group while keying its highlight off the project page rather than appPage.
  type NavItem = {
    to: string;
    key: string;
    icon: React.ReactNode;
    label: string;
    selectedOverride?: boolean;
    trailing?: React.ReactNode;
  };
  const groups: { label: string; items: NavItem[]; caption?: string }[] = [
    {
      label: t("app.navGroup.authentication", { defaultValue: "Auth" }),
      items: [
        { to: `${appBasePath}/auth-methods`, key: "auth-methods", icon: <Lock size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.authMethods", { defaultValue: "Auth Methods" }) },
        { to: `${appBasePath}/security`, key: "security", icon: <ShieldCheck size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.security", { defaultValue: "Auth settings" }) },
        { to: `${appBasePath}/members`, key: "members", icon: <Users size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.members", { defaultValue: "Users" }) },
        // Roles + Permissions are project-scoped (basePath, not appBasePath) and
        // shared across every environment — selection keys off the project page.
        { to: `${basePath}/roles`, key: "roles", icon: <IdCard size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("project.nav.roles"), selectedOverride: selectedValue === "roles" },
        { to: `${basePath}/permissions`, key: "permissions", icon: <KeyRound size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("project.nav.permissions"), selectedOverride: selectedValue === "permissions" },
        { to: `${appBasePath}/sessions`, key: "sessions", icon: <History size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.sessions", { defaultValue: "Sessions" }) },
        { to: `${appBasePath}/auth-logs`, key: "auth-logs", icon: <LogIn size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.authLogs", { defaultValue: "Auth Logs" }) },
        { to: `${appBasePath}/insights`, key: "insights", icon: <LineChart size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.insights", { defaultValue: "Insights" }) },
        // Branding is project-scoped (basePath, not appBasePath) — selection keys
        // off the project page, and it carries the premium ✨ marker.
        {
          to: `${basePath}/branding`,
          key: "branding",
          icon: <Palette size={ICON_SIZE} strokeWidth={ICON_STROKE} />,
          label: t("project.nav.branding"),
          selectedOverride: selectedValue === "branding",
          trailing: (
            <Box
              component="span"
              sx={{ display: "inline-flex", alignItems: "center", color: "primary.main", ml: 0.5, flexShrink: 0 }}
            >
              <Sparkles size={11} strokeWidth={2} aria-label={t("branding.premium")} />
            </Box>
          ),
        },
      ],
    },
    {
      label: t("app.navGroup.configuration", { defaultValue: "Configuration" }),
      items: [
        { to: appBasePath, key: "appDetail", icon: <Settings size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.summary", { defaultValue: "App Summary" }) },
        { to: `${appBasePath}/api-keys`, key: "api-keys", icon: <Key size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.apiKeys", { defaultValue: "API Keys" }) },
        { to: `${appBasePath}/webhooks`, key: "webhooks", icon: <Bell size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.webhooks", { defaultValue: "Webhooks" }) },
        { to: `${appBasePath}/features`, key: "features", icon: <Flag size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("project.nav.features", { defaultValue: "Feature Flags" }) },
        { to: `${appBasePath}/config`, key: "config", icon: <SlidersHorizontal size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("project.nav.config", { defaultValue: "Config Keys" }) },
        { to: `${appBasePath}/env-diff`, key: "env-diff", icon: <ArrowLeftRight size={ICON_SIZE} strokeWidth={ICON_STROKE} />, label: t("app.nav.envDiff", { defaultValue: "Env Diff" }) },
      ],
    },
  ];

  return (
    <Box
      sx={{
        position: "relative",
        ml: 1,
        pl: 1,
        mt: 0.25,
        mb: 0.5,
        borderLeft: "1px solid",
        borderColor: "divider",
      }}
    >
      {/* Env chip + switcher anchor the sub-tree. The app name itself
          is the page-header job — repeating it here is noise. */}
      <Box
        sx={{
          px: 1,
          pt: 0.5,
          pb: 0.75,
          display: "flex",
          alignItems: "center",
          gap: 0.75,
          minWidth: 0,
        }}
      >
        {appType && (
          <Chip
            size="small"
            label={appTypeLabel({ type: appType })}
            variant="outlined"
            sx={{
              height: 18,
              fontSize: 9.5,
              fontWeight: 600,
              letterSpacing: "0.08em",
              fontFamily: "var(--font-mono)",
              textTransform: "uppercase",
              flexShrink: 0,
              "& .MuiChip-label": { px: 0.75 },
              ...(appType === "prod" && { borderColor: "error.main", color: "error.main" }),
              ...(appType === "staging" && { borderColor: "warning.main", color: "warning.main" }),
              ...(appType === "dev" && { borderColor: "success.main", color: "success.main" }),
            }}
          />
        )}
        {onOpenSwitcher && (
          <Box
            component="button"
            onClick={(e: React.MouseEvent<HTMLButtonElement>) => onOpenSwitcher(e.currentTarget)}
            sx={{
              display: "inline-flex",
              alignItems: "center",
              gap: 0.25,
              px: 0.5,
              height: 18,
              ml: appType ? "auto" : -0.5,
              border: "none",
              borderRadius: 0.5,
              bgcolor: "transparent",
              color: "text.disabled",
              fontFamily: "inherit",
              fontSize: 10.5,
              fontWeight: 500,
              cursor: "pointer",
              flexShrink: 0,
              transition: "background-color 120ms ease, color 120ms ease",
              "&:hover": { bgcolor: "action.hover", color: "text.primary" },
            }}
          >
            {t("projectHome.switch")}
            <ChevronDown size={9} strokeWidth={1.75} />
          </Box>
        )}
      </Box>

      {groups.map((g, gi) => {
        const isCollapsed = collapsed.has(g.label);
        return (
          <Box
            key={g.label}
            sx={
              gi === 0
                ? { mt: 0.5 }
                : { mt: 1, pt: 1, borderTop: "1px solid", borderColor: "divider" }
            }
          >
            <Box
              component="button"
              type="button"
              onClick={() => toggleGroup(g.label)}
              aria-expanded={!isCollapsed}
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 0.75,
                width: "100%",
                px: 1,
                pt: 0.5,
                pb: 0.5,
                border: "none",
                bgcolor: "transparent",
                cursor: "pointer",
                borderRadius: 1,
                color: "text.secondary",
                fontFamily: "inherit",
                transition: "color 120ms ease",
                "&:hover": { color: "text.primary" },
                "&:hover .mr-group-chevron": { opacity: 1 },
              }}
            >
              <ChevronDown
                className="mr-group-chevron"
                size={12}
                strokeWidth={2}
                style={{
                  flexShrink: 0,
                  opacity: 0.65,
                  transition: "transform 140ms ease, opacity 120ms ease",
                  transform: isCollapsed ? "rotate(-90deg)" : "none",
                }}
              />
              <Typography sx={{ fontSize: 13.5, fontWeight: 700, letterSpacing: "0.01em" }}>
                {g.label}
              </Typography>
            </Box>
            <Collapse in={!isCollapsed} unmountOnExit>
              {g.caption && (
                <Typography
                  sx={{
                    pl: 3,
                    pr: 1,
                    mt: -0.25,
                    mb: 0.75,
                    fontSize: 11.5,
                    lineHeight: 1.35,
                    color: "text.disabled",
                  }}
                >
                  {g.caption}
                </Typography>
              )}
              <List disablePadding sx={{ display: "grid", gap: 0 }}>
                {g.items.map((it) => (
                  <SubNavItem
                    key={it.key}
                    to={it.to}
                    selected={it.selectedOverride ?? appPage === it.key}
                    icon={it.icon}
                    label={it.label}
                    trailing={it.trailing}
                  />
                ))}
              </List>
            </Collapse>
          </Box>
        );
      })}
    </Box>
  );
}

function Section({ label, children }: { label?: string; children: React.ReactNode }) {
  return (
    <>
      {label && (
        <Typography
          sx={{
            px: 1.25,
            pb: 0.5,
            pt: 1.25,
            display: "block",
            color: "text.disabled",
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            letterSpacing: "0.16em",
            fontWeight: 500,
            textTransform: "uppercase",
          }}
        >
          {label}
        </Typography>
      )}
      <List disablePadding sx={{ display: "grid", gap: 0, mt: label ? 0 : 0.5 }}>
        {children}
      </List>
    </>
  );
}

function NavItem({
  label,
  value,
  selected,
  basePath,
  icon,
  trailing,
  overrideTo,
}: {
  label: string;
  value: string;
  selected: string;
  basePath: string;
  icon: React.ReactNode;
  trailing?: React.ReactNode;
  // overrideTo lets a parent row navigate somewhere other than `${basePath}/${value}` —
  // used by group-parents like Authorization that land on a sub-item.
  overrideTo?: string;
}) {
  const isSel = selected === value;
  return (
    <ListItemButton
      component={Link}
      to={overrideTo ?? `${basePath}/${value}`}
      selected={isSel}
      sx={itemSx}
    >
      <ListItemIcon sx={iconSx}>{icon}</ListItemIcon>
      <ListItemText
        primary={label}
        primaryTypographyProps={{
          fontSize: 12.5,
          fontWeight: isSel ? 600 : 500,
        }}
      />
      {trailing}
    </ListItemButton>
  );
}

function SubNavItem({
  to,
  selected,
  icon,
  label,
  trailing,
}: {
  to: string;
  selected: boolean;
  icon: React.ReactNode;
  label: string;
  trailing?: React.ReactNode;
}) {
  return (
    <ListItemButton
      component={Link}
      to={to}
      selected={selected}
      sx={{ ...itemSx, px: 1 }}
    >
      <ListItemIcon sx={iconSx}>{icon}</ListItemIcon>
      <ListItemText
        primary={label}
        primaryTypographyProps={{
          fontSize: 12.5,
          fontWeight: selected ? 600 : 500,
        }}
      />
      {trailing}
    </ListItemButton>
  );
}
