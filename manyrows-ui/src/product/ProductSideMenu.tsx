import * as React from "react";
import {
  Box,
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
  Settings,
  IdCard,
  Layers,
  ShieldCheck,
  ArrowLeftRight,
  Palette,
  Sparkles,
} from "lucide-react";

interface Props {
  value: string;
  basePath: string; // e.g. "/app/workspace/123/products/456"
  workspaceBasePath: string; // e.g. "/app/workspace/123"
}

// Tighter density: nav items are ~28px tall with 10px horizontal
// padding and a thin 14px line-icon, matching the redesign mockup.
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

export default function ProductSideMenu({ value, basePath, workspaceBasePath }: Props) {
  const { t } = useTranslation();

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
      {/* Back to workspace */}
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

      <Section label={t("section.project")}>
        <NavItem
          label={t("project.nav.apps")}
          value="apps"
          icon={<Layers size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("project.nav.appDiff")}
          value="appDiff"
          icon={<ArrowLeftRight size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("project.nav.roles")}
          value="roles"
          icon={<IdCard size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("project.nav.permissions")}
          value="permissions"
          icon={<ShieldCheck size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
        <NavItem
          label={t("project.nav.branding")}
          value="branding"
          icon={<Palette size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
          badge={
            <Sparkles
              size={11}
              strokeWidth={2}
              aria-label={t("branding.premium")}
            />
          }
        />
        <NavItem
          label={t("project.nav.settings")}
          value="settings"
          icon={<Settings size={ICON_SIZE} strokeWidth={ICON_STROKE} />}
          selected={value}
          basePath={basePath}
        />
      </Section>
    </Box>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <>
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
      <List disablePadding sx={{ display: "grid", gap: 0 }}>
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
  badge,
}: {
  label: string;
  value: string;
  selected: string;
  basePath: string;
  icon: React.ReactNode;
  // Optional trailing mark (e.g. a Sparkles glyph flagging a premium page).
  badge?: React.ReactNode;
}) {
  const isSel = selected === value;
  return (
    <ListItemButton
      component={Link}
      to={`${basePath}/${value}`}
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
      {badge && (
        <Box
          component="span"
          sx={{
            display: "inline-flex",
            alignItems: "center",
            color: "primary.main",
            ml: 0.5,
            flexShrink: 0,
          }}
        >
          {badge}
        </Box>
      )}
    </ListItemButton>
  );
}
