import * as React from "react";
import { Box, Drawer, type DrawerProps, IconButton, Tooltip } from "@mui/material";
import { ChevronLeft, ChevronRight } from "lucide-react";

const STORAGE_KEY = "mr.drawerWide";
const SYNC_EVENT = "mr-drawer-wide";

function readPref(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

/**
 * Global, persisted "expand drawers" preference. Toggling it from any open
 * drawer updates every mounted WideDrawer (via a window event) and is
 * remembered across sessions and tabs.
 */
function useDrawerWide(): readonly [boolean, () => void] {
  const [wide, setWide] = React.useState(readPref);

  React.useEffect(() => {
    const sync = () => setWide(readPref());
    window.addEventListener(SYNC_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(SYNC_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  const toggle = React.useCallback(() => {
    const next = !readPref();
    try {
      localStorage.setItem(STORAGE_KEY, next ? "1" : "0");
    } catch {
      /* ignore unavailable storage */
    }
    setWide(next);
    window.dispatchEvent(new Event(SYNC_EVENT));
  }, []);

  return [wide, toggle] as const;
}

interface WideDrawerProps extends Omit<DrawerProps, "anchor"> {
  /** Collapsed width on sm+ screens, in px. */
  narrowWidth?: number;
  /** Expanded width on sm+ screens, in px (capped at 92vw). */
  wideWidth?: number;
}

/**
 * Right-anchored MUI Drawer with a chevron tab on its left edge that toggles
 * between a normal and a wide width. The expanded/collapsed state is shared
 * across every WideDrawer instance and persisted, so widening one drawer
 * widens them all.
 */
export default function WideDrawer({
  children,
  narrowWidth = 480,
  wideWidth = 880,
  PaperProps,
  ...rest
}: WideDrawerProps) {
  const [wide, toggle] = useDrawerWide();
  const width = wide ? wideWidth : narrowWidth;
  const { sx: paperSx, ...paperRest } = PaperProps ?? {};

  return (
    <Drawer
      anchor="right"
      {...rest}
      PaperProps={{
        ...paperRest,
        sx: {
          width: { xs: "100%", sm: width },
          maxWidth: "92vw",
          overflow: "visible", // let the toggle tab poke out past the left edge
          transition: (theme) =>
            theme.transitions.create("width", {
              duration: theme.transitions.duration.shorter,
            }),
          ...paperSx,
        },
      }}
    >
      <Tooltip title={wide ? "Narrow" : "Widen"} placement="left">
        <IconButton
          onClick={toggle}
          aria-label={wide ? "Narrow drawer" : "Widen drawer"}
          sx={{
            position: "absolute",
            top: "50%",
            left: 0,
            transform: "translate(-100%, -50%)",
            display: { xs: "none", sm: "flex" },
            width: 24,
            height: 48,
            p: 0,
            borderRadius: "8px 0 0 8px",
            bgcolor: "background.paper",
            color: "text.secondary",
            border: (theme) => `1px solid ${theme.palette.divider}`,
            borderRight: "none",
            boxShadow: "-2px 0 6px rgba(0, 0, 0, 0.08)",
            "&:hover": { bgcolor: "action.hover", color: "text.primary" },
          }}
        >
          {wide ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
        </IconButton>
      </Tooltip>
      {/*
        The Paper above uses overflow:visible so the tab can poke past the left
        edge, which disables the Paper's own vertical scroll. This wrapper
        restores it for drawers whose content grows past the viewport.
      */}
      <Box sx={{ flex: 1, minHeight: 0, overflowY: "auto" }}>{children}</Box>
    </Drawer>
  );
}
