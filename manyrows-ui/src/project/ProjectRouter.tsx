import {useApp} from "../App.tsx";
import {useParams} from "react-router-dom";
import ProjectHome from "./ProjectHome.tsx";
import {Box} from "@mui/material";
import { useTranslation } from "react-i18next";

export default function ProjectRouter() {
  const app = useApp();
  const params = useParams();
  const { t } = useTranslation();
  const workspaceId = params["workspaceId"]
  const projectId = params["projectId"]
  const appId = params["appId"]
  const appPage = params["appPage"]
  const ws = app.appData.workspaces.find(w => w.id === workspaceId)
  if (!ws) {
    return <Box sx={{ p: 2 }}>{t("projectRouter.noWorkspaceSelected")}</Box>
  }
  if (!projectId) {
    return <Box sx={{ p: 2 }}>{t("projectRouter.noProjectSelected")}</Box>
  }
  // The standalone "Project" summary page was removed: it only listed
  // apps, which the Apps page does in full. The project now lands
  // directly on Apps, and any old "/home" bookmark redirects there.
  const projectPage = params["projectPage"] === "home" ? "apps" : params["projectPage"]
  const page = appId ? "appDetail" : (projectPage ?? "apps")
  return <ProjectHome page={page} projectId={projectId} workspace={ws} appId={appId} appPage={appPage} />
}