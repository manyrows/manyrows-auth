import * as React from "react";
import { Button, Dialog, DialogActions, DialogContent, DialogTitle } from "@mui/material";

export interface ConfirmActionDialogProps {
  open: boolean;
  loading: boolean;
  title: React.ReactNode;
  children: React.ReactNode;
  cancelLabel: string;
  confirmLabel: string;
  loadingLabel?: string;
  confirmColor?: "primary" | "error";
  onClose: () => void;
  onConfirm: () => void;
}

// ConfirmActionDialog — presentational shell for the small "are you sure?"
// dialogs (enable/disable, clear password, reset 2FA, delete, prune, ...).
// The parent owns all state and the async confirm handler (open/close/reload/
// snackbar logic stays at the call site, passed in via onConfirm), so this
// only unifies the repeated Dialog/Title/Content/Actions + loading-aware
// confirm button boilerplate.
export default function ConfirmActionDialog(props: ConfirmActionDialogProps) {
  return (
    <Dialog open={props.open} onClose={props.loading ? undefined : props.onClose} maxWidth="xs" fullWidth>
      <DialogTitle>{props.title}</DialogTitle>
      <DialogContent>{props.children}</DialogContent>
      <DialogActions>
        <Button onClick={props.onClose} disabled={props.loading}>{props.cancelLabel}</Button>
        <Button
          variant="contained"
          disableElevation
          color={props.confirmColor ?? "primary"}
          disabled={props.loading}
          onClick={props.onConfirm}
        >
          {props.loading ? (props.loadingLabel ?? "...") : props.confirmLabel}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
