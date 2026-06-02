import {
  Outlet,
  useNavigate,
  useOutletContext,
  useSearchParams,
  useLocation,
} from "react-router-dom";
import { Box, CircularProgress } from "@mui/material";
import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import AppHeader from "./AppHeader.tsx";
import type { Account, Workspace } from "./core.ts";
import { setLanguageFromUser } from "./i18n";
import { useAdminAuthConfig, resetAdminAuthConfigCache } from "./hooks/useAdminAuthConfig";

const Login = lazy(() => import("./Login.tsx"));
const Register = lazy(() => import("./Register.tsx"));
const Validate = lazy(() => import("./Validate.tsx"));
const ForgotPassword = lazy(() => import("./ForgotPassword.tsx"));

export interface AppData {
  account: Account;
  workspaces: Workspace[];
  baseUrl: string;
  env: string;
  /** Server build version (config.BuildVersion). Surfaced in the account menu. */
  version?: string;
}

interface AppContext {
  appData: AppData;
  refreshAppData: () => void;
}

export function useApp() {
  return useOutletContext<AppContext>();
}

const getAppData = async (): Promise<AppData> => {
  const res = await axios.get<AppData>("/admin/appdata");
  return res.data;
};

export default function App() {
  // ---- hooks MUST be called unconditionally, before any return ----
  const [appData, setAppData] = useState<AppData | null>(null);
  const [loading, setLoading] = useState(true);

  const nav = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const x = searchParams.get("x");
  const xBool = x === "true";

  const onLoggedInSuccess = () => {
    fetchAppData()
    nav(`/app`)
  }

  const fetchAppData = useCallback(() => {
    setLoading(true);
    return getAppData()
      .then((data) => {
        setAppData(data);
        // Sync i18n language from user preference
        if (data?.account?.language) {
          setLanguageFromUser(data.account.language);
        }
      })
      .catch((err) => {
        if (err?.response?.status === 401) {
          setAppData(null);
        }
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  const handleLogout = useCallback(() => {
    axios.post("/admin/logout").catch(() => {}).finally(() => {
      try { localStorage.removeItem("manyrows:lastEmail"); } catch { /* ignore */ }
      // Drop cached auth config so the next visit refetches
      // needsFirstAdmin (it'll be false now that an admin exists).
      resetAdminAuthConfigCache();
      setAppData(null);
      nav(`/app`);
    });
  }, [nav]);

  useEffect(() => {
    fetchAppData();
  }, [fetchAppData]);

  const authenticated = useMemo(() => {
    return appData !== null && appData.account !== undefined;
  }, [appData]);

  const authCfg = useAdminAuthConfig();
  const authPage = useMemo<"login" | "register" | "forgot">(() => {
    const p = (location.pathname || "").toLowerCase();

    // match both exact and nested (in case you ever do /app/auth/login etc)
    if (p === "/app/login" || p.endsWith("/login")) return "login";
    if (p === "/app/register" || p.endsWith("/register")) return "register";
    if (p === "/app/forgot" || p.endsWith("/forgot")) return "forgot";
    // First-boot: no super-admin claimed yet → land on register so
    // the operator's first interaction is "create your account" not
    // "sign in" (there's nothing to sign into).
    if (authCfg?.needsFirstAdmin) return "register";
    return "login";
  }, [location.pathname, authCfg?.needsFirstAdmin]);

  // ---- rendering ----
  if (loading) {
    return (
      <Box sx={{ p: 4, display: "flex", justifyContent: "center" }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!authenticated) {
    return (
      <Suspense fallback={<Box sx={{ p: 4, display: "flex", justifyContent: "center" }}><CircularProgress /></Box>}>
        {authPage === "forgot" ? <ForgotPassword onSuccess={onLoggedInSuccess} />
          : authPage === "register" ? <Register onSuccess={onLoggedInSuccess} />
          : <Login onSuccess={onLoggedInSuccess} />}
      </Suspense>
    );
  }

  if (appData?.account && !appData.account.validatedAt) {
    return (
      <Suspense fallback={<Box sx={{ p: 4, display: "flex", justifyContent: "center" }}><CircularProgress /></Box>}>
        <Validate account={appData.account} onSuccess={onLoggedInSuccess} />
      </Suspense>
    );
  }

  if (xBool) {
    return (
      <Outlet
        context={
          {
            appData: appData!,
            refreshAppData: fetchAppData,
          } satisfies AppContext
        }
      />
    );
  }

  return (
    <>
      <AppHeader handleLogout={handleLogout} appData={appData!} />
      <Outlet
        context={
          {
            appData: appData!,
            refreshAppData: fetchAppData,
          } satisfies AppContext
        }
      />
    </>
  );
}
