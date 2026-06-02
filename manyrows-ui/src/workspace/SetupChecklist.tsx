import * as React from "react";
import axios from "axios";
import {
  Box,
  Button,
  IconButton,
  LinearProgress,
  Paper,
  Stack,
  Tooltip,
  Typography,
} from "@mui/material";
import { Check, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router-dom";

import type { Workspace } from "../core.ts";

interface Props {
  workspace: Workspace;
  // Called after a successful dismiss POST so the parent can update
  // its workspace state without a full refetch.
  onDismissed: () => void;
}

interface ChecklistItem {
  key: string;
  title: string;
  subtitle: string;
  done: boolean;
  // When set, the row becomes a button that navigates / runs the action.
  action?: { kind: "navigate"; to: string } | { kind: "info" };
}

// Stripe-style first-boot setup card. Renders on the workspace home
// (WorkspaceSummary) until either dismissed or every item completes.
export default function SetupChecklist({ workspace, onDismissed }: Props) {
  const { t } = useTranslation();
  const nav = useNavigate();

  const [busy, setBusy] = React.useState(false);

  const projectCount = (workspace.projects ?? []).length;
  const testSent = !!workspace.setupTestEmailSentAt;

  // Single "email delivery verified" item subsumes the prior three
  // (transport + sender address + test). A delivered test email is
  // proof-of-life: transport works AND the from-address passed
  // DKIM/SPF AND the operator has actually seen something land.
  const items: ChecklistItem[] = [
    {
      key: "super-admin",
      title: t("setup.superAdmin.title", { defaultValue: "Super-admin account created" }),
      subtitle: t("setup.superAdmin.subtitle", { defaultValue: "You're signed in as the super-admin." }),
      done: true,
    },
    {
      key: "email",
      title: t("setup.email.title", { defaultValue: "Email delivery verified" }),
      subtitle: testSent
        ? t("setup.email.subtitle.done", {
            defaultValue: "A test email was delivered successfully.",
          })
        : t("setup.email.subtitle.todo", {
            defaultValue:
              "Send a test from Email Settings to verify your transport and sender address work.",
          }),
      done: testSent,
      action: { kind: "navigate", to: `/app/workspace/${workspace.id}/emailSettings` },
    },
    {
      key: "first-app",
      title: t("setup.firstApp.title", { defaultValue: "First app created" }),
      subtitle: projectCount > 0
        ? t("setup.firstApp.subtitle.done", {
            defaultValue: "{{count}} project(s) ready.",
            count: projectCount,
          })
        : t("setup.firstApp.subtitle.todo", {
            defaultValue: "Run the Quick Start wizard from the Get Started panel below.",
          }),
      done: projectCount > 0,
    },
  ];

  const completedCount = items.filter((i) => i.done).length;
  const totalCount = items.length;
  const allDone = completedCount === totalCount;

  // Auto-hide once every item is done. The dismissed_at timestamp is
  // for early-exits; if you completed everything, the card has
  // served its purpose.
  if (allDone) return null;

  const dismiss = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await axios.post(`/admin/workspace/${workspace.id}/setup-checklist/dismiss`);
      onDismissed();
    } catch {
      // No snackbar here - dismissing is best-effort; if it failed
      // they'll just see the card again on next load.
    } finally {
      setBusy(false);
    }
  };

  const handleAction = (item: ChecklistItem) => {
    if (!item.action) return;
    if (item.action.kind === "navigate") {
      nav(item.action.to);
    }
  };

  return (
    <Paper
      variant="outlined"
      sx={{
        borderRadius: 2.5,
        p: 0,
        overflow: "hidden",
      }}
    >
      <Stack
        direction="row"
        alignItems="center"
        justifyContent="space-between"
        sx={{ px: 2.5, py: 1.75, borderBottom: 1, borderColor: "divider" }}
      >
        <Stack spacing={0.25}>
          <Typography sx={{ fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" }}>
            {t("setup.title", { defaultValue: "Complete your setup" })}
          </Typography>
          <Typography
            sx={{
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              letterSpacing: "0.04em",
              color: "text.disabled",
            }}
          >
            {completedCount} / {totalCount} done
          </Typography>
        </Stack>
        <Tooltip title={t("setup.dismiss", { defaultValue: "Dismiss" })}>
          <span>
            <IconButton size="small" onClick={dismiss} disabled={busy}>
              <X size={14} strokeWidth={1.75} />
            </IconButton>
          </span>
        </Tooltip>
      </Stack>
      <LinearProgress
        variant="determinate"
        value={(completedCount / totalCount) * 100}
        sx={{ height: 3 }}
      />
      <Stack divider={<Box sx={{ borderTop: 1, borderColor: "divider" }} />}>
        {items.map((item) => {
          const clickable = !!item.action && !item.done;
          return (
            <Stack
              key={item.key}
              direction="row"
              spacing={1.5}
              alignItems="center"
              sx={{
                px: 2.5,
                py: 1.5,
                cursor: clickable ? "pointer" : "default",
                "&:hover": clickable ? { bgcolor: "action.hover" } : {},
              }}
              onClick={clickable ? () => handleAction(item) : undefined}
            >
              <Box
                sx={{
                  width: 20,
                  height: 20,
                  borderRadius: "50%",
                  display: "grid",
                  placeItems: "center",
                  bgcolor: item.done ? "text.primary" : "transparent",
                  border: item.done ? "1.5px solid" : "1.5px solid",
                  borderColor: item.done ? "text.primary" : "divider",
                  color: item.done ? "background.default" : "transparent",
                  flexShrink: 0,
                  transition: "background-color 160ms ease, border-color 160ms ease",
                }}
              >
                {item.done && <Check size={12} strokeWidth={3} />}
              </Box>
              <Stack spacing={0.25} sx={{ flex: 1, minWidth: 0 }}>
                <Typography
                  sx={{
                    fontSize: 13.5,
                    fontWeight: 500,
                    color: item.done ? "text.secondary" : "text.primary",
                    textDecoration: item.done ? "line-through" : "none",
                  }}
                >
                  {item.title}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {item.subtitle}
                </Typography>
              </Stack>
              {clickable && (
                <Button size="small" variant="text" sx={{ flexShrink: 0, textTransform: "none" }}>
                  {t("setup.action", { defaultValue: "Set up" })}
                </Button>
              )}
            </Stack>
          );
        })}
      </Stack>
    </Paper>
  );
}
