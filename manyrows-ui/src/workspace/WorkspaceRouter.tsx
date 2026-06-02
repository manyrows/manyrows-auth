import {useApp} from "../App.tsx";
import {useParams} from "react-router-dom";
import WorkspaceHome from "./WorkspaceHome.tsx";
import {Box} from "@mui/material";
import {useTranslation} from "react-i18next";

export default function WorkspaceRouter() {
  const app = useApp();
  const { t } = useTranslation();
  const params = useParams();
  const id = params["workspaceId"]
  const ws = app.appData.workspaces.find(w => w.id === id)
  if (!ws) {
    return <Box sx={{ p: 2 }}>{t("workspace.noWorkspaceSelected")}</Box>
  }
  const poolId = params["poolId"]
  // When poolId is present, the path is the pool-detail surface. The
  // optional :workspacePage segment selects the tab inside that page
  // (defaults to "overview"). Without poolId, :workspacePage is the
  // workspace section (settings, users, etc.).
  const rawPage = params["workspacePage"]
  const page = poolId ? (rawPage ?? "overview") : (rawPage ?? "home")
  return <WorkspaceHome page={page} workspace={ws} poolId={poolId} />
}