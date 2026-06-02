// Router.tsx
import * as React from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import App from "./App.tsx";
import Home from "./Home.tsx";
import Loader from "./Loader.tsx";

const WorkspaceRouter = React.lazy(() => import("./workspace/WorkspaceRouter.tsx"));
const Profile = React.lazy(() => import("./profile/Profile.tsx"));
const ProjectRouter = React.lazy(() => import("./project/ProjectRouter.tsx"));
const NotFound = React.lazy(() => import("./NotFound.tsx"));

export default function Router() {
  return (
    <BrowserRouter>
      <React.Suspense fallback={<Loader />}>
      <Routes>
        {/* Root -> App shell (keeps your existing pattern) */}
        <Route path="" element={<App />}>
          <Route index element={<Home />} />
        </Route>

        {/* Everything under /app goes through App.tsx */}
        <Route path="app" element={<App />}>
          <Route index element={<Home />} />

          {/* These are "auth routes" that App.tsx will render as full-page auth screens.
              The element here can be a placeholder since App.tsx returns early for these paths. */}
          <Route path="register" element={<Home />} />
          <Route path="login" element={<Home />} />
          <Route path="forgot" element={<Home />} />

          <Route path="profile" element={<Profile />} />
          <Route path="workspace/:workspaceId" element={<WorkspaceRouter />} />
          <Route path="workspace/:workspaceId/projects/:projectId" element={<ProjectRouter />} />
          <Route path="workspace/:workspaceId/projects/:projectId/apps/:appId" element={<ProjectRouter />} />
          <Route path="workspace/:workspaceId/projects/:projectId/apps/:appId/:appPage" element={<ProjectRouter />} />
          <Route path="workspace/:workspaceId/projects/:projectId/:projectPage" element={<ProjectRouter />} />
          <Route path="workspace/:workspaceId/userPools/:poolId" element={<WorkspaceRouter />} />
          <Route path="workspace/:workspaceId/userPools/:poolId/:workspacePage" element={<WorkspaceRouter />} />
          <Route path="workspace/:workspaceId/:workspacePage" element={<WorkspaceRouter />} />
          <Route path="*" element={<NotFound />} />
        </Route>

        <Route path="*" element={<NotFound />} />
      </Routes>
      </React.Suspense>
    </BrowserRouter>
  );
}
