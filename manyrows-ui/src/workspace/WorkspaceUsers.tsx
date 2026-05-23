import * as React from "react";
import axios from "axios";
import type { Workspace } from "../core.ts";

import { useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  InputAdornment,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import Loader from "../Loader.tsx";
import PageHeader from "../components/PageHeader.tsx";
import EmptyState from "../components/EmptyState.tsx";
import { extractApiError } from "../lib/apiError.ts";
import { Users, Search } from "lucide-react";

interface Props {
  workspace: Workspace;
}

type AppRef = { id: string; name: string; productId: string };
type ScopeRef = { type: "pool"; poolId?: string; poolName?: string };

// One row per account. The same email can appear more than once when it
// exists in more than one pool — each is a distinct account row (the
// list is server-paginated, so cross-pool grouping isn't possible).
type UserRow = {
  id: string;
  email: string;
  enabled: boolean;
  source?: string;
  apps: AppRef[];
  poolId?: string;
  poolName?: string;
};

type RawAccount = {
  id: string;
  email: string;
  enabled?: boolean;
  source?: string;
  apps?: AppRef[];
  scopes?: ScopeRef[];
};

const monoLabelSx = {
  fontFamily: "var(--font-mono)",
  textTransform: "uppercase" as const,
  letterSpacing: "0.14em",
  fontSize: 10,
  fontWeight: 500,
  color: "text.disabled" as const,
};

export default function WorkspaceUsers({ workspace }: Props) {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [users, setUsers] = React.useState<UserRow[] | null>(null);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState<string | null>(null);
  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const [page, setPage] = React.useState(0);
  const [pageSize, setPageSize] = React.useState(25);
  const [selectedUser, setSelectedUser] = React.useState<UserRow | null>(null);

  // Debounce the search box; reset to page 0 whenever the query settles
  // so the page slice and the pager stay coherent.
  React.useEffect(() => {
    const id = setTimeout(() => {
      setDebouncedSearch(search.trim());
      setPage(0);
    }, 300);
    return () => clearTimeout(id);
  }, [search]);

  // Server-paginated + filtered fetch. Keyed on page/search inputs;
  // deliberately NOT on users/loading — setLoading(true) below would
  // otherwise mutate a dep, tear the effect down mid-flight via the
  // `alive` cleanup, and drop the in-flight response.
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    setErr(null);
    axios
      .get<{ accounts?: RawAccount[]; total?: number }>(`/admin/workspace/${workspace.id}/accounts`, {
        params: { page, pageSize, ...(debouncedSearch ? { email: debouncedSearch } : {}) },
      })
      .then((res) => {
        if (!alive) return;
        const rows: UserRow[] = (res.data?.accounts ?? []).map((a) => {
          const poolScope = (a.scopes ?? []).find((s) => s.type === "pool");
          return {
            id: a.id,
            email: a.email,
            enabled: a.enabled !== false,
            source: a.source,
            apps: a.apps ?? [],
            poolId: poolScope?.poolId,
            poolName: poolScope?.poolName,
          };
        });
        setUsers(rows);
        setTotal(typeof res.data?.total === "number" ? res.data.total : rows.length);
      })
      .catch((e) => {
        if (alive) setErr(extractApiError(e, t("workspaceUsers.loadFailed")));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => { alive = false; };
  }, [workspace.id, page, pageSize, debouncedSearch]);

  if (loading && users === null) return <Loader />;

  const rows = users ?? [];
  const pristineEmpty = total === 0 && !debouncedSearch && !loading;

  return (
    <Stack spacing={2.5}>
      <PageHeader
        title={t("workspaceUsers.title")}
        subtitle={t("workspaceUsers.subtitle")}
      />

      {err && <Alert severity="error">{err}</Alert>}

      {pristineEmpty ? (
        <EmptyState
          icon={<Users size={18} strokeWidth={1.75} />}
          title={t("workspaceUsers.empty.title")}
          description={t("workspaceUsers.empty.description")}
        />
      ) : (
        <>
          <TextField
            size="small"
            placeholder={t("workspaceUsers.searchPlaceholder")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <Search size={14} strokeWidth={1.75} />
                </InputAdornment>
              ),
            }}
            sx={{ maxWidth: 360 }}
          />

          <TableContainer component={Paper} variant="outlined">
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("workspaceUsers.col.email")}</TableCell>
                  <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("workspaceUsers.col.pool")}</TableCell>
                  <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("workspaceUsers.col.apps")}</TableCell>
                  <TableCell sx={{ fontWeight: 600, fontSize: 12 }}>{t("workspaceUsers.col.status")}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((u) => (
                  <TableRow key={u.id} hover sx={{ cursor: "pointer" }} onClick={() => setSelectedUser(u)}>
                    <TableCell>
                      <Typography variant="body2">{u.email}</Typography>
                    </TableCell>
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      {u.poolId ? (
                        <Chip
                          label={u.poolName ?? u.poolId}
                          size="small"
                          clickable
                          onClick={() => navigate(`/app/workspace/${workspace.id}/userPools`)}
                          sx={{ height: 20, fontSize: 11, borderColor: "primary.main", color: "primary.main" }}
                          variant="outlined"
                        />
                      ) : (
                        <Typography variant="caption" color="text.secondary">-</Typography>
                      )}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                        {u.apps.length > 0 ? (
                          u.apps.map((a) => (
                            <Chip
                              key={a.id}
                              label={a.name}
                              size="small"
                              clickable
                              onClick={(e) => {
                                e.stopPropagation();
                                navigate(`/app/workspace/${workspace.id}/products/${a.productId}/apps/${a.id}/members?email=${encodeURIComponent(u.email)}`);
                              }}
                              sx={{ height: 20, fontSize: 11 }}
                            />
                          ))
                        ) : (
                          <Typography variant="caption" color="text.secondary">{t("workspaceUsers.noAppMemberships")}</Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={u.enabled ? t("workspaceUsers.statusEnabled") : t("workspaceUsers.statusDisabled")}
                        variant={u.enabled ? "filled" : "outlined"}
                        sx={{
                          height: 20,
                          fontSize: 11,
                          ...(u.enabled
                            ? { bgcolor: "success.main", color: "#fff" }
                            : { borderColor: "error.main", color: "error.main" }),
                        }}
                      />
                    </TableCell>
                  </TableRow>
                ))}
                {rows.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} sx={{ textAlign: "center", py: 3 }}>
                      <Typography variant="body2" color="text.secondary">
                        {t("workspaceUsers.noSearchResults")}
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>

          <TablePagination
            component="div"
            count={total}
            page={page}
            onPageChange={(_, p) => setPage(p)}
            rowsPerPage={pageSize}
            onRowsPerPageChange={(e) => {
              setPageSize(parseInt(e.target.value, 10));
              setPage(0);
            }}
            rowsPerPageOptions={[25, 50, 100]}
          />
        </>
      )}

      {/* User Detail Dialog */}
      <Dialog open={!!selectedUser} onClose={() => setSelectedUser(null)} fullWidth maxWidth="sm">
        <DialogTitle>{t("workspaceUsers.detailTitle")}</DialogTitle>
        <DialogContent>
          {selectedUser && (
            <Stack spacing={2} sx={{ pt: 1 }}>
              <Stack spacing={0.5}>
                <Typography sx={monoLabelSx}>{t("workspaceUsers.col.email")}</Typography>
                <Typography variant="body2">{selectedUser.email}</Typography>
              </Stack>

              <Divider />

              <Stack direction="row" spacing={3}>
                <Stack spacing={0.25}>
                  <Typography sx={monoLabelSx}>{t("workspaceUsers.idLabel")}</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
                    {selectedUser.id}
                  </Typography>
                </Stack>
                <Stack spacing={0.25}>
                  <Typography sx={monoLabelSx}>{t("workspaceUsers.col.status")}</Typography>
                  <Chip
                    size="small"
                    label={selectedUser.enabled ? t("workspaceUsers.statusEnabled") : t("workspaceUsers.statusDisabled")}
                    color={selectedUser.enabled ? "success" : "default"}
                    variant={selectedUser.enabled ? "filled" : "outlined"}
                    sx={{ height: 20, fontSize: 11, width: "fit-content" }}
                  />
                </Stack>
                {selectedUser.source && (
                  <Stack spacing={0.25}>
                    <Typography sx={monoLabelSx}>{t("workspaceUsers.sourceLabel")}</Typography>
                    <Typography variant="body2">{selectedUser.source}</Typography>
                  </Stack>
                )}
              </Stack>

              <Stack direction="row" spacing={3}>
                <Stack spacing={0.25}>
                  <Typography sx={monoLabelSx}>{t("workspaceUsers.col.pool")}</Typography>
                  {selectedUser.poolId ? (
                    <Chip
                      label={selectedUser.poolName ?? selectedUser.poolId}
                      size="small"
                      clickable
                      variant="outlined"
                      onClick={() => {
                        setSelectedUser(null);
                        navigate(`/app/workspace/${workspace.id}/userPools`);
                      }}
                      sx={{ height: 20, fontSize: 11, borderColor: "primary.main", color: "primary.main", width: "fit-content" }}
                    />
                  ) : (
                    <Typography variant="body2" color="text.secondary">-</Typography>
                  )}
                </Stack>
                <Stack spacing={0.25}>
                  <Typography sx={monoLabelSx}>{t("workspaceUsers.col.apps")}</Typography>
                  <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                    {selectedUser.apps.length > 0 ? (
                      selectedUser.apps.map((a) => (
                        <Chip
                          key={a.id}
                          label={a.name}
                          size="small"
                          clickable
                          onClick={() => {
                            const email = selectedUser.email;
                            setSelectedUser(null);
                            navigate(`/app/workspace/${workspace.id}/products/${a.productId}/apps/${a.id}/members?email=${encodeURIComponent(email)}`);
                          }}
                          sx={{ height: 20, fontSize: 11 }}
                        />
                      ))
                    ) : (
                      <Typography variant="body2" color="text.secondary">-</Typography>
                    )}
                  </Box>
                </Stack>
              </Stack>
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelectedUser(null)}>{t("common.close")}</Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
