import * as React from "react";
import { apiJson } from "../lib/api.ts";
import { useTranslation } from "react-i18next";
import { extractApiError } from "../lib/apiError.ts";
import type {
  ConfigKey,
  ConfigValue,
  App,
  FeatureFlag,
  FeatureFlagOverride,
  Project,
  Workspace,
} from "../core.ts";
import { appDisplayName, appTypeLabel } from "../core.ts";
import { alpha } from "../colors.ts";
import {
  Alert,
  Box,
  Chip,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import PageHeader from "../components/PageHeader.tsx";

interface Props {
  project: Project;
  workspace: Workspace;
  /** Locked left side — the currently-open app. The user picks the right. */
  appId: string;
}

export default function AppDiff({ project, appId }: Props) {
  const { t } = useTranslation();
  const base = `/admin/workspace/${project.workspaceId}/projects/${project.id}`;

  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const [apps, setApps] = React.useState<App[]>([]);
  const [configKeys, setConfigKeys] = React.useState<ConfigKey[]>([]);
  const [configValues, setConfigValues] = React.useState<ConfigValue[]>([]);
  const [flags, setFlags] = React.useState<FeatureFlag[]>([]);
  const [flagEnvs, setFlagEnvs] = React.useState<FeatureFlagOverride[]>([]);

  // Left is always the current app from the URL. Right is user-picked.
  const leftAppId = appId;
  const [rightAppId, setRightAppId] = React.useState("");


  async function refreshAll() {
    setLoading(true);
    setError(null);
    try {
      const [envRes, keyRes, valRes, flagRes, flagEnvRes] = await Promise.all([
        apiJson<{ apps: App[] }>(`${base}/apps`),
        apiJson<{ configKeys: ConfigKey[] }>(`${base}/configKeys`),
        apiJson<{ configValues: ConfigValue[] }>(`${base}/configValues`),
        apiJson<{ featureFlags: FeatureFlag[] }>(`${base}/featureFlags`),
        apiJson<{ featureFlagOverrides: FeatureFlagOverride[] }>(`${base}/featureFlags/apps`),
      ]);

      const nextApps = envRes?.apps || [];
      const nextKeys = keyRes?.configKeys || [];
      const nextVals = valRes?.configValues || [];
      const nextFlags = flagRes?.featureFlags || [];
      const nextFlagEnvs = flagEnvRes?.featureFlagOverrides || [];

      type FlagWire = FeatureFlag & { visibility?: string };
      (nextFlags as FlagWire[]).forEach((f) => {
        if (!f) return;
        if (f.scope === undefined || f.scope === null || f.scope === "") {
          if (f.visibility !== undefined && f.visibility !== null && f.visibility !== "") {
            f.scope = f.visibility;
          } else {
            f.scope = "server";
          }
        }
      });

      setApps(nextApps);
      setConfigKeys(nextKeys);
      setConfigValues(nextVals);
      setFlags(nextFlags);
      setFlagEnvs(nextFlagEnvs);

      // Default the right side to the first app that isn't the current one.
      setRightAppId((prev) => {
        if (prev && prev !== appId && nextApps.some((e) => e.id === prev)) return prev;
        const other = nextApps.find((e) => e.id !== appId);
        return other?.id ?? "";
      });
    } catch (e) {
      setError(extractApiError(e, t("appDiff.failedToLoad", { defaultValue: "Failed to load data" })));
    } finally {
      setLoading(false);
    }
  }


  React.useEffect(() => {
    void refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [project.id, appId]);

  const valueMap = React.useMemo(() => {
    const m = new Map<string, ConfigValue>();
    configValues.forEach((v) => m.set(`${v.configKeyId}::${v.appId}`, v));
    return m;
  }, [configValues]);

  const flagEnvMap = React.useMemo(() => {
    const m = new Map<string, FeatureFlagOverride>();
    flagEnvs.forEach((fe) => m.set(`${fe.featureFlagId}::${fe.appId}`, fe));
    return m;
  }, [flagEnvs]);

  const activeKeys = React.useMemo(
    () => configKeys.filter((k) => k.status === "active"),
    [configKeys],
  );

  const activeFlags = React.useMemo(
    () => flags.filter((f) => f.status === "active"),
    [flags],
  );

  const bothSelected = leftAppId && rightAppId && leftAppId !== rightAppId;

  function getConfigDisplay(key: ConfigKey, appId: string): string {
    if (key.exposure === "secret") return t("appDiff.secret");
    const cv = valueMap.get(`${key.id}::${appId}`);
    if (!cv || cv.value === undefined || cv.value === null) return t("appDiff.notSet");
    if (typeof cv.value === "object") return JSON.stringify(cv.value);
    return String(cv.value);
  }

  function configValuesDiffer(key: ConfigKey, leftId: string, rightId: string): boolean {
    if (key.exposure === "secret") {
      const leftCv = valueMap.get(`${key.id}::${leftId}`);
      const rightCv = valueMap.get(`${key.id}::${rightId}`);
      const leftHas = leftCv?.hasSecret ?? false;
      const rightHas = rightCv?.hasSecret ?? false;
      return leftHas !== rightHas;
    }
    const left = getConfigDisplay(key, leftId);
    const right = getConfigDisplay(key, rightId);
    return left !== right;
  }

  function getFlagEnabled(flag: FeatureFlag, appId: string): { enabled: boolean; isDefault: boolean } {
    const fe = flagEnvMap.get(`${flag.id}::${appId}`);
    if (fe) return { enabled: fe.enabled, isDefault: false };
    return { enabled: flag.defaultEnabled, isDefault: true };
  }

  function flagsDiffer(flag: FeatureFlag, leftId: string, rightId: string): boolean {
    const left = getFlagEnabled(flag, leftId);
    const right = getFlagEnabled(flag, rightId);
    return left.enabled !== right.enabled;
  }

  const configDiffCount = React.useMemo(() => {
    if (!bothSelected) return 0;
    return activeKeys.filter((k) => configValuesDiffer(k, leftAppId, rightAppId)).length;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeKeys, leftAppId, rightAppId, valueMap]);

  const flagDiffCount = React.useMemo(() => {
    if (!bothSelected) return 0;
    return activeFlags.filter((f) => flagsDiffer(f, leftAppId, rightAppId)).length;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeFlags, leftAppId, rightAppId, flagEnvMap]);

  const leftApp = apps.find((e) => e.id === leftAppId);
  const rightApp = apps.find((e) => e.id === rightAppId);

  const diffBg = alpha("#DC2626", 0.07);

  return (
    <Box>
      <PageHeader title={t("appDiff.title")} mb={3} />

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {loading && (
        <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
          <CircularProgress size={28} />
        </Box>
      )}

      {!loading && (
        <>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems="center" sx={{ mb: 3 }}>
            <Stack sx={{ minWidth: 200 }}>
              <Typography
                sx={{
                  fontFamily: "var(--font-mono)",
                  textTransform: "uppercase",
                  letterSpacing: "0.14em",
                  fontSize: 10.5,
                  fontWeight: 500,
                  color: "text.disabled",
                }}
              >
                {t("appDiff.selectLeft", { defaultValue: "Left" })}
              </Typography>
              <Typography sx={{ fontSize: 14, fontWeight: 500 }}>
                {(() => {
                  const a = apps.find((e) => e.id === appId);
                  return a ? `${appDisplayName(a)} · ${appTypeLabel(a)}` : appId;
                })()}
              </Typography>
            </Stack>

            <Typography sx={{ color: "text.disabled", fontSize: 16 }}>↔</Typography>

            <FormControl size="small" sx={{ minWidth: 200 }}>
              <InputLabel>{t("appDiff.selectRight")}</InputLabel>
              <Select
                value={rightAppId}
                label={t("appDiff.selectRight")}
                onChange={(e) => setRightAppId(e.target.value)}
              >
                {apps
                  .filter((app) => app.id !== appId)
                  .map((app) => (
                    <MenuItem key={app.id} value={app.id}>
                      {`${appDisplayName(app)} - ${appTypeLabel(app)}`}
                    </MenuItem>
                  ))}
              </Select>
            </FormControl>
          </Stack>

          {!bothSelected && (
            <Alert severity="info" sx={{ mb: 2 }}>
              {t("appDiff.selectBoth")}
            </Alert>
          )}

          {bothSelected && (
            <>
              <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
                {configDiffCount === 0 && flagDiffCount === 0 ? (
                  <Chip
                    label={t("appDiff.identical")}
                    color="success"
                    size="small"
                    variant="outlined"
                    sx={{ fontWeight: 500 }}
                  />
                ) : (
                  <>
                    <Chip
                      label={t("appDiff.configDiffs", { count: configDiffCount })}
                      color={configDiffCount > 0 ? "error" : "success"}
                      size="small"
                      variant="outlined"
                      sx={{ fontWeight: 500 }}
                    />
                    <Chip
                      label={t("appDiff.flagDiffs", { count: flagDiffCount })}
                      color={flagDiffCount > 0 ? "error" : "success"}
                      size="small"
                      variant="outlined"
                      sx={{ fontWeight: 500 }}
                    />
                  </>
                )}

              </Stack>

              <Typography sx={{ fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.14em", fontSize: 10, fontWeight: 500, color: "text.disabled", mb: 1 }}>
                {t("appDiff.configSection")}
              </Typography>

              {activeKeys.length === 0 ? (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                  {t("appDiff.noDiffs")}
                </Typography>
              ) : (
                <TableContainer sx={{ mb: 4 }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 600 }}>{t("appDiff.key")}</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>{appTypeLabel(leftApp)}</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>{appTypeLabel(rightApp)}</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {activeKeys.map((key) => {
                        const differs = configValuesDiffer(key, leftAppId, rightAppId);
                        return (
                          <TableRow key={key.id} sx={differs ? { bgcolor: diffBg } : undefined}>
                            <TableCell>
                              <Stack direction="row" spacing={1} alignItems="center">
                                <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
                                  {key.key}
                                </Typography>
                                <Chip label={key.valueType} size="small" variant="outlined" sx={{ fontSize: 11, height: 20 }} />
                              </Stack>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
                                {getConfigDisplay(key, leftAppId)}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
                                {getConfigDisplay(key, rightAppId)}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}

              <Typography sx={{ fontFamily: "var(--font-mono)", textTransform: "uppercase", letterSpacing: "0.14em", fontSize: 10, fontWeight: 500, color: "text.disabled", mb: 1 }}>
                {t("appDiff.featuresSection")}
              </Typography>

              {activeFlags.length === 0 ? (
                <Typography variant="body2" color="text.secondary">
                  {t("appDiff.noDiffs")}
                </Typography>
              ) : (
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ fontWeight: 600 }}>{t("appDiff.key")}</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>{appTypeLabel(leftApp)}</TableCell>
                        <TableCell sx={{ fontWeight: 600 }}>{appTypeLabel(rightApp)}</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {activeFlags.map((flag) => {
                        const differs = flagsDiffer(flag, leftAppId, rightAppId);
                        const leftState = getFlagEnabled(flag, leftAppId);
                        const rightState = getFlagEnabled(flag, rightAppId);
                        return (
                          <TableRow key={flag.id} sx={differs ? { bgcolor: diffBg } : undefined}>
                            <TableCell>
                              <Stack direction="row" spacing={1} alignItems="center">
                                <Typography variant="body2" sx={{ fontFamily: "var(--font-mono)", fontSize: 13 }}>
                                  {flag.key}
                                </Typography>
                                <Chip
                                  label={flag.scope === "client" ? "client" : "server"}
                                  size="small"
                                  variant="outlined"
                                  sx={{ fontSize: 11, height: 20 }}
                                />
                              </Stack>
                            </TableCell>
                            <TableCell>
                              <Stack direction="row" spacing={0.5} alignItems="center">
                                <Chip
                                  label={leftState.enabled ? t("appDiff.on", { defaultValue: "ON" }) : t("appDiff.off", { defaultValue: "OFF" })}
                                  size="small"
                                  color={leftState.enabled ? "success" : "default"}
                                  sx={{ fontSize: 11, height: 20, fontWeight: 600 }}
                                />
                                {leftState.isDefault && (
                                  <Typography variant="caption" color="text.secondary">
                                    {t("appDiff.default")}
                                  </Typography>
                                )}
                              </Stack>
                            </TableCell>
                            <TableCell>
                              <Stack direction="row" spacing={0.5} alignItems="center">
                                <Chip
                                  label={rightState.enabled ? t("appDiff.on", { defaultValue: "ON" }) : t("appDiff.off", { defaultValue: "OFF" })}
                                  size="small"
                                  color={rightState.enabled ? "success" : "default"}
                                  sx={{ fontSize: 11, height: 20, fontWeight: 600 }}
                                />
                                {rightState.isDefault && (
                                  <Typography variant="caption" color="text.secondary">
                                    {t("appDiff.default")}
                                  </Typography>
                                )}
                              </Stack>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </>
          )}
        </>
      )}

    </Box>
  );
}
