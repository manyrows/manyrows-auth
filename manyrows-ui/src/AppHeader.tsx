import * as React from "react";
import {
  AppBar,
  Avatar,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  IconButton,
  ListItemIcon,
  Menu,
  MenuItem,
  Stack,
  Toolbar,
  Typography,
} from "@mui/material";
import { BookOpen, Check, ChevronDown, LogOut, Plus, TriangleAlert, User as UserIcon } from "lucide-react";
import { type AppData } from "./App.tsx";
import { useNavigate, useLocation } from "react-router-dom";
import { Logo } from "./Logo.tsx";
import { useTranslation } from "react-i18next";
import LanguagePicker from "./components/LanguagePicker";

interface AppHeaderProps {
  appData: AppData;
  handleLogout: () => void;
}

function initialsFromEmail(email: string): string {
  const left = (email || "").split("@")[0] || "";
  const parts = left.split(/[._-]+/).filter(Boolean);
  const a = (parts[0]?.[0] ?? left[0] ?? "U").toUpperCase();
  const b = (parts[1]?.[0] ?? "").toUpperCase();
  return (a + b).slice(0, 2);
}

// Parse /app/workspace/:wsId[/projects/:projectId][/...] from the current pathname.
function parseRouteContext(pathname: string): { workspaceId?: string; projectId?: string } {
  const m = pathname.match(/^\/app\/workspace\/([^/]+)(?:\/projects\/([^/]+))?/);
  return { workspaceId: m?.[1], projectId: m?.[2] };
}

export default function AppHeader(props: AppHeaderProps) {
  const { appData } = props;
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const { t } = useTranslation();

  const [loading, setLoading] = React.useState(false);
  const [acctAnchor, setAcctAnchor] = React.useState<null | HTMLElement>(null);
  const acctOpen = Boolean(acctAnchor);
  const [projAnchor, setProjAnchor] = React.useState<null | HTMLElement>(null);
  const projOpen = Boolean(projAnchor);
  const [confirmOpen, setConfirmOpen] = React.useState(false);

  const email = appData.account.email;
  const serverVersion = appData.version || "";

  // Route context - drives the in-header breadcrumb / switcher
  const { workspaceId, projectId } = parseRouteContext(pathname);
  const currentWorkspace = workspaceId
    ? appData.workspaces.find((w) => w.id === workspaceId)
    : undefined;
  const currentProject = currentWorkspace?.projects?.find((p) => p.id === projectId);

  const openAcct = (e: React.MouseEvent<HTMLElement>) => setAcctAnchor(e.currentTarget);
  const closeAcct = () => setAcctAnchor(null);

  const openProj = (e: React.MouseEvent<HTMLElement>) => setProjAnchor(e.currentTarget);
  const closeProj = () => setProjAnchor(null);

  const switchProject = (id: string) => {
    if (workspaceId) navigate(`/app/workspace/${workspaceId}/projects/${id}`);
    closeProj();
  };

  const goProfile = () => {
    closeAcct();
    navigate("/app/profile");
  };

  const requestLogout = () => {
    closeAcct();
    setConfirmOpen(true);
  };

  const closeConfirm = () => setConfirmOpen(false);

  const confirmLogout = async () => {
    if (loading) return;
    setLoading(true);
    try {
      closeConfirm();
      props.handleLogout();
    } finally {
      setLoading(false);
    }
  };

  const projects = currentWorkspace?.projects ?? [];

  return (
    <Box sx={{ position: "sticky", top: 0, zIndex: (t) => t.zIndex.appBar }}>
      <AppBar
        position="static"
        elevation={0}
        color="transparent"
        sx={{
          borderBottom: "1px solid",
          borderColor: "divider",
          backdropFilter: "blur(14px) saturate(140%)",
          bgcolor: "rgba(250,250,248,0.85)",
        }}
      >
        <Toolbar
          disableGutters
          variant="dense"
          sx={{
            minHeight: "52px !important",
            height: 52,
            px: 2.5,
            gap: 1,
          }}
        >
          <Logo />

          {/* In-header nav: home + workspace breadcrumb + project switcher */}
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 0.75,
              ml: 1.5,
              minWidth: 0,
              flex: 1,
            }}
          >
            {/* Self-hosted runs with a single workspace and no picker,
                so the workspace name is omitted entirely - only the
                project switcher acts as the contextual breadcrumb. */}

            {currentWorkspace && projects.length > 0 && (
              <>
                <Crumb separator />
                <Button
                  onClick={openProj}
                  size="small"
                  endIcon={
                    <ChevronDown
                      size={11}
                      strokeWidth={2}
                      style={{
                        transition: "transform 160ms ease",
                        transform: projOpen ? "rotate(180deg)" : "rotate(0deg)",
                      }}
                    />
                  }
                  aria-haspopup="true"
                  aria-expanded={projOpen ? "true" : undefined}
                  sx={{
                    textTransform: "none",
                    color: currentProject ? "text.primary" : "text.secondary",
                    fontWeight: currentProject ? 600 : 500,
                    fontSize: 13,
                    minWidth: 0,
                    px: 0.75,
                    height: 28,
                    maxWidth: 240,
                    "&:hover": { bgcolor: "action.hover" },
                    "& .MuiButton-endIcon": { ml: 0.5, color: "text.disabled" },
                    "& > span": {
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    },
                    ...(projOpen && { bgcolor: "action.selected" }),
                  }}
                >
                  <span>
                    {currentProject ? currentProject.name : t("header.selectProject")}
                  </span>
                </Button>

                <Menu
                  anchorEl={projAnchor}
                  open={projOpen}
                  onClose={closeProj}
                  anchorOrigin={{ vertical: "bottom", horizontal: "left" }}
                  transformOrigin={{ vertical: "top", horizontal: "left" }}
                  PaperProps={{
                    elevation: 0,
                    sx: {
                      mt: 0.5,
                      minWidth: 240,
                      maxWidth: 320,
                    },
                  }}
                >
                  <Typography
                    sx={{
                      display: "block",
                      px: 2,
                      pt: 1,
                      pb: 0.5,
                      color: "text.disabled",
                      fontFamily: "var(--font-mono)",
                      fontWeight: 500,
                      fontSize: 10,
                      letterSpacing: "0.16em",
                      textTransform: "uppercase",
                    }}
                  >
                    {t("header.projectsLabel", { name: currentWorkspace.name })}
                  </Typography>
                  {projects.map((p) => (
                    <MenuItem
                      key={p.id}
                      onClick={() => switchProject(p.id)}
                      selected={p.id === projectId}
                    >
                      <ListItemIcon sx={{ minWidth: 26, color: "primary.main" }}>
                        {p.id === projectId ? <Check size={13} strokeWidth={2.5} /> : null}
                      </ListItemIcon>
                      <Box sx={{ minWidth: 0, flex: 1 }}>
                        <Typography
                          sx={{
                            fontSize: 13,
                            fontWeight: p.id === projectId ? 600 : 500,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {p.name}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                  <Divider sx={{ my: 0.5 }} />
                  <MenuItem
                    onClick={() => {
                      closeProj();
                      navigate(`/app/workspace/${workspaceId}`);
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 26, color: "text.secondary" }}>
                      <Plus size={13} strokeWidth={2} />
                    </ListItemIcon>
                    <Typography sx={{ fontSize: 13, color: "text.secondary" }}>
                      {t("header.manageProjects")}
                    </Typography>
                  </MenuItem>
                </Menu>
              </>
            )}
          </Box>

          {/* Build version - small mono tag so support / operators can
              read it without opening any menu. Kept lowercase so git
              SHAs and -dirty stay readable. */}
          {serverVersion && (
            <Typography
              component="span"
              sx={{
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                color: "text.disabled",
                fontWeight: 500,
                px: 0.75,
                whiteSpace: "nowrap",
                display: { xs: "none", sm: "inline" },
              }}
              title={t("header.serverBuildVersion", { version: serverVersion })}
            >
              {serverVersion}
            </Typography>
          )}

          {/* Language picker - persists to the signed-in admin's account */}
          <LanguagePicker persist />

          {/* API docs */}
          <Button
            component="a"
            href="https://manyrows.com/docs"
            target="_blank"
            rel="noopener noreferrer"
            size="small"
            startIcon={<BookOpen size={13} strokeWidth={1.75} />}
            sx={{
              color: "text.secondary",
              fontWeight: 500,
              fontSize: 13,
              px: 1,
              height: 28,
              "&:hover": { color: "text.primary", bgcolor: "action.hover" },
              "& .MuiButton-startIcon": { mr: 0.75 },
            }}
          >
            {t("nav.docs")}
          </Button>

          {/* Account button - initials avatar inside the header so the
              user can see at a glance who they're signed in as. */}
          <IconButton
            onClick={openAcct}
            size="small"
            aria-label={t("header.accountMenu")}
            aria-controls={acctOpen ? "account-menu" : undefined}
            aria-haspopup="true"
            aria-expanded={acctOpen ? "true" : undefined}
            sx={{
              p: 0.25,
              ml: 0.25,
              ...(acctOpen ? { bgcolor: "action.selected" } : null),
            }}
          >
            <Avatar
              sx={{
                width: 26,
                height: 26,
                fontSize: 11,
                fontWeight: 600,
                letterSpacing: "0.02em",
                bgcolor: "text.primary",
                color: "background.default",
              }}
            >
              {initialsFromEmail(email)}
            </Avatar>
          </IconButton>

          <Menu
            id="account-menu"
            anchorEl={acctAnchor}
            open={acctOpen}
            onClose={closeAcct}
            anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
            transformOrigin={{ vertical: "top", horizontal: "right" }}
            PaperProps={{
              elevation: 0,
              sx: {
                mt: 0.5,
                borderRadius: 2.5,
                minWidth: 240,
                overflow: "hidden",
                border: "1px solid",
                borderColor: "divider",
                boxShadow: "0 4px 12px rgba(0,0,0,0.08)",
              },
            }}
            MenuListProps={{ sx: { py: 0.5 } }}
          >
            {/* Header */}
            <Box sx={{ px: 2, py: 1.5, borderBottom: "1px solid", borderColor: "divider" }}>
              <Stack direction="row" spacing={1.5} alignItems="center">
                <Avatar
                  sx={{
                    width: 36,
                    height: 36,
                    fontSize: 14,
                    fontWeight: 600,
                    bgcolor: "primary.main",
                    color: "white",
                  }}
                >
                  {initialsFromEmail(email)}
                </Avatar>
                <Box sx={{ minWidth: 0 }}>
                  <Typography variant="body2" sx={{ fontWeight: 500, lineHeight: 1.3 }}>
                    {email}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {t("common.signedIn")}
                  </Typography>
                </Box>
              </Stack>
            </Box>

            <MenuItem onClick={goProfile}>
              <ListItemIcon sx={{ minWidth: 30, color: "text.secondary" }}>
                <UserIcon size={14} strokeWidth={1.75} />
              </ListItemIcon>
              <Box>
                <Typography variant="body2">{t("profile.title")}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {t("profile.viewDetails")}
                </Typography>
              </Box>
            </MenuItem>


            <MenuItem onClick={requestLogout} disabled={loading}>
              <ListItemIcon sx={{ minWidth: 30, color: "text.secondary" }}>
                <LogOut size={14} strokeWidth={1.75} />
              </ListItemIcon>
              <Box>
                <Typography variant="body2">{t("auth.signOut")}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {t("logout.message")}
                </Typography>
              </Box>
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>

      {/* Logout confirmation */}
      <Dialog
        open={confirmOpen}
        onClose={loading ? undefined : closeConfirm}
        aria-labelledby="logout-title"
        PaperProps={{
          sx: {
            minWidth: { xs: "auto", sm: 420 },
          },
        }}
      >
        <DialogTitle
          id="logout-title"
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 1,
          }}
        >
          <TriangleAlert size={14} strokeWidth={1.75} />
          {t("logout.title")}
        </DialogTitle>

        <DialogContent sx={{ pt: 0.5 }}>
          <Typography variant="body2" color="text.secondary">
            {t("logout.message")}
          </Typography>
        </DialogContent>

        <DialogActions sx={{ px: 2.5, pb: 2, gap: 1 }}>
          <Button onClick={closeConfirm} disabled={loading}>
            {t("common.cancel")}
          </Button>
          <Button variant="contained" onClick={confirmLogout} disabled={loading}>
            {loading ? t("auth.loggingOut") : t("auth.signOut")}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

function Crumb({ separator }: { separator?: boolean }) {
  if (!separator) return null;
  return (
    <Typography
      component="span"
      sx={{
        fontFamily: "var(--font-mono)",
        fontSize: 12,
        color: "text.disabled",
        userSelect: "none",
        mx: 0.25,
        opacity: 0.7,
      }}
    >
      /
    </Typography>
  );
}
