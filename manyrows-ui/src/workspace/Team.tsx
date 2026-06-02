import * as React from "react";
import axios from "axios";
import { extractApiError } from "../lib/apiError.ts";
import {
  Alert,
  Avatar,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import { UserPlus, Trash2, Mail } from "lucide-react";
import PageHeader from "../components/PageHeader.tsx";
import { useSnackbar } from "notistack";
import { useTranslation } from "react-i18next";
import type { Workspace } from "../core.ts";

interface Props {
  workspace: Workspace;
}

type TeamMember = {
  id: string;
  accountId: string;
  email: string;
  name: string;
  role: string;
  createdAt: string;
};

type TeamInvite = {
  id: string;
  email: string;
  invitedByName: string;
  status: string;
  createdAt: string;
};

function initialsFromEmail(email: string) {
  const base = (email || "?").split("@")[0] || "?";
  const parts = base.split(/[._-]+/).filter(Boolean);
  const a = parts[0]?.[0] ?? base[0] ?? "?";
  const b = parts[1]?.[0] ?? "";
  return (a + b).toUpperCase();
}

const roleColor: Record<string, "primary" | "default"> = {
  owner: "primary",
  admin: "default",
};

export default function Team({ workspace }: Props) {
  const { enqueueSnackbar } = useSnackbar();
  const { t } = useTranslation();

  const [loading, setLoading] = React.useState(true);
  const [members, setMembers] = React.useState<TeamMember[]>([]);
  const [invites, setInvites] = React.useState<TeamInvite[]>([]);
  const [callerRole, setCallerRole] = React.useState("");

  const [addOpen, setAddOpen] = React.useState(false);
  const [addEmail, setAddEmail] = React.useState("");
  const [addBusy, setAddBusy] = React.useState(false);
  const [addError, setAddError] = React.useState<string | null>(null);
  const [removeTarget, setRemoveTarget] = React.useState<TeamMember | null>(null);

  const isOwner = callerRole === "owner" || workspace.role === "owner";

  const refresh = React.useCallback(async () => {
    try {
      const [teamRes, invitesRes] = await Promise.all([
        axios.get(`/admin/workspace/${workspace.id}/team`),
        axios.get(`/admin/workspace/${workspace.id}/team/invites`),
      ]);
      setMembers(teamRes.data.members || []);
      setCallerRole(teamRes.data.callerRole || "");
      setInvites(invitesRes.data.invites || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [workspace.id]);

  React.useEffect(() => {
    refresh();
  }, [refresh]);

  const onAdd = async () => {
    if (!addEmail.trim()) return;
    setAddBusy(true);
    setAddError(null);
    try {
      const res = await axios.post(`/admin/workspace/${workspace.id}/team`, {
        email: addEmail.trim(),
      });
      if (res.data?.invited) {
        enqueueSnackbar(t("team.invited"), { variant: "success" });
      } else {
        enqueueSnackbar(t("team.added"), { variant: "success" });
      }
      setAddOpen(false);
      setAddEmail("");
      refresh();
    } catch (e) {
      setAddError(extractApiError(e, t("error.generic")));
    } finally {
      setAddBusy(false);
    }
  };

  const onRemove = async () => {
    if (!removeTarget) return;
    try {
      await axios.delete(
        `/admin/workspace/${workspace.id}/team/${removeTarget.accountId}`,
      );
      enqueueSnackbar(t("team.removed"), { variant: "success" });
      setRemoveTarget(null);
      refresh();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("error.generic")), { variant: "error" });
      setRemoveTarget(null);
    }
  };

  const onCancelInvite = async (inviteId: string) => {
    try {
      await axios.delete(
        `/admin/workspace/${workspace.id}/team/invites/${inviteId}`,
      );
      enqueueSnackbar(t("team.inviteCancelled"), { variant: "success" });
      refresh();
    } catch (e) {
      enqueueSnackbar(extractApiError(e, t("error.generic")), { variant: "error" });
    }
  };

  if (loading) return null;

  return (
    <Box>
      <Stack spacing={2} sx={{ maxWidth: 820 }}>
        <PageHeader
          title={t("team.title")}
          subtitle={t("team.description")}
          action={
            isOwner ? (
              <Button
                startIcon={<UserPlus size={14} strokeWidth={1.75} />}
                variant="contained"
                size="small"
                onClick={() => {
                  setAddOpen(true);
                  setAddEmail("");
                  setAddError(null);
                }}
              >
                {t("team.addMember")}
              </Button>
            ) : null
          }
        />

        <Stack spacing={0}>
          {members.map((m) => (
            <Stack
              key={m.id}
              direction="row"
              spacing={1.5}
              alignItems="center"
              sx={{
                py: 1.25,
                px: 1,
                borderBottom: "1px solid",
                borderColor: "divider",
                "&:last-child": { borderBottom: "none" },
              }}
            >
              <Avatar
                sx={{
                  width: 32,
                  height: 32,
                  fontSize: 13,
                  bgcolor: "action.selected",
                  color: "primary.main",
                }}
              >
                {initialsFromEmail(m.email)}
              </Avatar>

              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography
                  sx={{
                    fontSize: 14,
                    fontWeight: 500,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {m.name || m.email}
                </Typography>
                {m.name && (
                  <Typography
                    variant="body2"
                    color="text.secondary"
                    sx={{ fontSize: 12 }}
                  >
                    {m.email}
                  </Typography>
                )}
              </Box>

              <Chip
                size="small"
                label={m.role === "owner" ? t("team.owner") : t("team.admin")}
                color={roleColor[m.role] || "default"}
                variant="outlined"
                sx={{ fontWeight: 500, fontSize: 11, height: 22 }}
              />

              {isOwner && m.role !== "owner" && (
                <Tooltip title={t("team.removeConfirm")}>
                  <IconButton
                    size="small"
                    color="error"
                    onClick={() => setRemoveTarget(m)}
                  >
                    <Trash2 size={14} strokeWidth={1.75} />
                  </IconButton>
                </Tooltip>
              )}
            </Stack>
          ))}

          {members.length === 0 && (
            <Alert severity="info">
              {t("team.noMembers")}
            </Alert>
          )}
        </Stack>

        {/* Pending invites */}
        {invites.length > 0 && (
          <>
            <Typography variant="subtitle2" color="text.secondary" sx={{ pt: 1 }}>
              {t("team.pendingInvites")}
            </Typography>
            <Stack spacing={0}>
              {invites.map((inv) => (
                <Stack
                  key={inv.id}
                  direction="row"
                  spacing={1.5}
                  alignItems="center"
                  sx={{
                    py: 1.25,
                    px: 1,
                    borderBottom: "1px solid",
                    borderColor: "divider",
                    opacity: 0.75,
                    "&:last-child": { borderBottom: "none" },
                  }}
                >
                  <Avatar
                    sx={{
                      width: 32,
                      height: 32,
                      fontSize: 13,
                      bgcolor: "action.selected",
                      color: "primary.main",
                    }}
                  >
                    <Mail size={16} strokeWidth={1.75} />
                  </Avatar>

                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Typography
                      sx={{
                        fontSize: 14,
                        fontWeight: 500,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {inv.email}
                    </Typography>
                  </Box>

                  <Chip
                    size="small"
                    label={t("team.pending")}
                    variant="outlined"
                    sx={{ fontWeight: 500, fontSize: 11, height: 22 }}
                  />

                  {isOwner && (
                    <Tooltip title={t("team.cancelInvite")}>
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => onCancelInvite(inv.id)}
                      >
                        <Trash2 size={14} strokeWidth={1.75} />
                      </IconButton>
                    </Tooltip>
                  )}
                </Stack>
              ))}
            </Stack>
          </>
        )}
      </Stack>

      {/* Add member dialog */}
      <Dialog
        open={addOpen}
        onClose={() => !addBusy && setAddOpen(false)}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>{t("team.addMember")}</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            label={t("team.emailLabel")}
            placeholder={t("team.emailPlaceholder")}
            value={addEmail}
            onChange={(e) => setAddEmail(e.target.value)}
            fullWidth
            size="small"
            disabled={addBusy}
            sx={{ mt: 1 }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                onAdd();
              }
            }}
          />
          {addError && (
            <Alert severity="error" sx={{ mt: 1.5, borderRadius: 2 }}>
              {addError}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddOpen(false)} disabled={addBusy}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="contained"
            onClick={onAdd}
            disabled={addBusy || !addEmail.trim()}
          >
            {addBusy ? t("team.adding") : t("team.addMember")}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Remove member confirmation dialog */}
      <Dialog open={!!removeTarget} onClose={() => setRemoveTarget(null)}>
        <DialogTitle>{t("team.removeTitle")}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t("team.removeConfirm")}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRemoveTarget(null)}>
            {t("common.cancel")}
          </Button>
          <Button color="error" variant="contained" onClick={onRemove}>
            {t("common.remove")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
