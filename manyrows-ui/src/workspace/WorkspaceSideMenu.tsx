import * as React from "react";
import {
  Box,
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
  FolderKanban,
  Users,
  Settings,
  UserCog,
  Mail,
  KeyRound,
  Cookie,
  Boxes,
  Fingerprint,
  ChevronDown,
} from "lucide-react";

interface Props {
  /** Active nav value - maps to the workspacePage URL segment. */
  value: string;
  /** Workspace base path, e.g. "/app/workspace/123". */
  basePath: string;
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

// WorkspaceSideMenu surfaces every workspace-level page in a left
// rail so Settings / Team / Email aren't hidden behind a single
// "Settings" button. Mirrors ProjectSideMenu density
// and styling so the chrome reads as one piece across all three
// admin levels.
// Workspace-level auth pages — the "Global Auth" section. Used to keep that
// section expanded when one of its pages is active even though it's collapsed
// by default.
const AUTH_VALUES = ["users", "userPools", "sso", "cookieDomain", "signingKeys"];

export default function WorkspaceSideMenu({ value, basePath }: Props) {
  const { t } = useTranslation();
  const inAuth = AUTH_VALUES.includes(value);

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
      <Section label={t("section.workspace", { defaultValue: "Workspace" })} first>
        <NavItem
          label={t("workspace.nav.projects", { defaultValue: "Projects" })}
          value="home"
          icon={<FolderKanban size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("workspace.nav.settings", { defaultValue: "Settings" })}
          value="settings"
          icon={<Settings size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("workspace.nav.team", { defaultValue: "Team" })}
          value="team"
          icon={<UserCog size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("workspace.nav.email", { defaultValue: "Email" })}
          value="emailSettings"
          icon={<Mail size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
      </Section>

      <Section
        label={t("section.auth", { defaultValue: "Global Auth" })}
        defaultCollapsed
        activeWithin={inAuth}
      >
        <NavItem
          label={t("workspace.nav.sso", { defaultValue: "SSO" })}
          value="sso"
          icon={<Fingerprint size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("workspace.nav.userSummary", { defaultValue: "User Summary" })}
          value="users"
          icon={<Users size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("workspace.nav.userPools", { defaultValue: "User pools" })}
          value="userPools"
          icon={<Boxes size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("workspace.nav.cookieDomain", { defaultValue: "Cookie domain" })}
          value="cookieDomain"
          icon={<Cookie size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("workspace.nav.signingKeys", { defaultValue: "JWT signing keys" })}
          value="signingKeys"
          icon={<KeyRound size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
      </Section>
    </Box>
  );
}

// Collapsible nav group. Styled to match ProjectSideMenu's AppSubNav groups
// (bold sentence-case title, hover-reveal chevron, a thin top-border rule
// between groups) so the workspace and project rails read as one system.
function Section({
  label,
  children,
  first,
  defaultCollapsed,
  activeWithin,
}: {
  label: string;
  children: React.ReactNode;
  // First group sits flush; later groups get a top-border rule separating them.
  first?: boolean;
  defaultCollapsed?: boolean;
  // When true the section holds the active page — keep it open even though it
  // would otherwise be collapsed by default.
  activeWithin?: boolean;
}) {
  // Start collapsed unless the active page lives inside; navigating into the
  // section later re-opens it, but a manual toggle while inside still sticks.
  const [collapsed, setCollapsed] = React.useState(!!defaultCollapsed && !activeWithin);
  React.useEffect(() => {
    if (activeWithin) setCollapsed(false);
  }, [activeWithin]);

  return (
    <Box sx={first ? { mt: 0.5 } : { mt: 1, pt: 1, borderTop: "1px solid", borderColor: "divider" }}>
      <Box
        component="button"
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        aria-expanded={!collapsed}
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
          textAlign: "left",
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
            transform: collapsed ? "rotate(-90deg)" : "none",
          }}
        />
        <Typography sx={{ fontSize: 13.5, fontWeight: 700, letterSpacing: "0.01em" }}>
          {label}
        </Typography>
      </Box>
      <Collapse in={!collapsed} unmountOnExit>
        <List disablePadding sx={{ display: "grid", gap: 0 }}>
          {children}
        </List>
      </Collapse>
    </Box>
  );
}

function NavItem({
  label,
  value,
  selected,
  basePath,
  icon,
}: {
  label: string;
  value: string;
  selected: string;
  basePath: string;
  icon: React.ReactNode;
}) {
  const isSel = selected === value;
  // "home" doesn't append a suffix - it's the bare workspace path.
  const to = value === "home" ? basePath : `${basePath}/${value}`;
  return (
    <ListItemButton component={Link} to={to} selected={isSel} sx={itemSx}>
      <ListItemIcon sx={iconSx}>{icon}</ListItemIcon>
      <ListItemText
        primary={label}
        primaryTypographyProps={{
          fontSize: 12.5,
          fontWeight: isSel ? 600 : 500,
        }}
      />
    </ListItemButton>
  );
}
