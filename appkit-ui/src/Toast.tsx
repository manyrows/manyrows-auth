import * as React from "react";
import Icon from "./Icon";

type AlertSeverity = "error" | "success" | "info" | "warning";

type Toast = {
  id: number;
  message: string;
  severity: AlertSeverity;
};

type ToastContextValue = {
  showToast: (message: string, severity?: AlertSeverity) => void;
  showSuccess: (message: string) => void;
  showError: (message: string) => void;
};

const ToastContext = React.createContext<ToastContextValue | null>(null);

let toastId = 0;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([]);

  const showToast = React.useCallback((message: string, severity: AlertSeverity = "info") => {
    const id = ++toastId;
    setToasts((prev) => [...prev, { id, message, severity }]);
  }, []);

  const showSuccess = React.useCallback((message: string) => {
    showToast(message, "success");
  }, [showToast]);

  const showError = React.useCallback((message: string) => {
    showToast(message, "error");
  }, [showToast]);

  const handleClose = React.useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  // Auto-dismiss
  React.useEffect(() => {
    if (toasts.length === 0) return;
    const latest = toasts[toasts.length - 1];
    const timer = setTimeout(() => handleClose(latest.id), 4000);
    return () => clearTimeout(timer);
  }, [toasts, handleClose]);

  const ctx = React.useMemo(
    () => ({ showToast, showSuccess, showError }),
    [showToast, showSuccess, showError]
  );

  return (
    <ToastContext.Provider value={ctx}>
      {children}
      {toasts.length > 0 && (
        <div className="ak-snackbar-container" role="status" aria-live="polite">
          {toasts.map((toast) => (
            <div key={toast.id} className={`ak-snackbar ak-alert-filled-${toast.severity}`}>
              <div className="ak-alert" style={{ background: "transparent", color: "inherit" }}>
                <span className="ak-alert-content">{toast.message}</span>
                <button className="ak-alert-close" onClick={() => handleClose(toast.id)} aria-label="Close">
                  <Icon name="close" size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = React.useContext(ToastContext);
  if (!ctx) {
    return {
      showToast: () => {},
      showSuccess: () => {},
      showError: () => {},
    };
  }
  return ctx;
}
