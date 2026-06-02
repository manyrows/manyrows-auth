import * as React from "react";
import type { App } from "../core.ts";
import { isProdApp } from "../core.ts";

// useEnvSwitch owns the app/environment picker state shared by the ConfigKeys
// and Features screens: the selected app, and the "you're switching to a
// production app — are you sure?" confirmation gate. Switching to a prod app
// is deferred behind a confirm dialog; non-prod apps switch immediately.
//
// The two screens differ only in side-effects, supplied via opts:
//   - onApply: extra work when the selection actually changes (ConfigKeys
//     clears its per-(key,app) draft/dirty state).
//   - onConfirmProd / onCancelProd: Features shows info snackbars; ConfigKeys
//     stays silent.
export interface UseEnvSwitchOptions {
  onApply?: (nextAppId: string) => void;
  onConfirmProd?: (nextAppId: string) => void;
  onCancelProd?: () => void;
}

export function useEnvSwitch(apps: App[], fixedAppId: string | undefined, opts?: UseEnvSwitchOptions) {
  // Keep as string (not null) so MUI select behaves predictably.
  const [selectedAppId, setSelectedAppId] = React.useState<string>(fixedAppId || "");

  React.useEffect(() => {
    if (fixedAppId) setSelectedAppId(fixedAppId);
  }, [fixedAppId]);

  const selectedApp = React.useMemo(
    () => apps.find((e) => e.id === selectedAppId) || null,
    [apps, selectedAppId],
  );

  // Prod confirm dialog state.
  const [prodConfirmOpen, setProdConfirmOpen] = React.useState(false);
  const [pendingAppId, setPendingAppId] = React.useState<string>("");
  const pendingApp = React.useMemo(
    () => apps.find((e) => e.id === pendingAppId) || null,
    [apps, pendingAppId],
  );

  function applyEnvSwitch(nextAppId: string) {
    setSelectedAppId(nextAppId);
    opts?.onApply?.(nextAppId);
  }

  function requestEnvSwitch(nextAppId: string) {
    if (!nextAppId || nextAppId === selectedAppId) return;

    const nextApp = apps.find((e) => e.id === nextAppId) || null;
    if (isProdApp(nextApp)) {
      setPendingAppId(nextAppId);
      setProdConfirmOpen(true);
      return;
    }

    applyEnvSwitch(nextAppId);
  }

  // resetProdConfirm dismisses an open confirm without firing onCancelProd —
  // used when the underlying data reloads out from under the dialog.
  function resetProdConfirm() {
    setProdConfirmOpen(false);
    setPendingAppId("");
  }

  function confirmProdSwitch() {
    const next = pendingAppId;
    resetProdConfirm();
    if (!next) return;
    applyEnvSwitch(next);
    opts?.onConfirmProd?.(next);
  }

  function cancelProdSwitch() {
    resetProdConfirm();
    opts?.onCancelProd?.();
  }

  return {
    selectedAppId,
    setSelectedAppId,
    selectedApp,
    prodConfirmOpen,
    pendingApp,
    requestEnvSwitch,
    confirmProdSwitch,
    cancelProdSwitch,
    resetProdConfirm,
  };
}
