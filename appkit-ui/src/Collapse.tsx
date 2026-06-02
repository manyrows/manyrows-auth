import * as React from "react";

export default function Collapse({
  show,
  children,
  unmountOnExit = true,
}: {
  show: boolean;
  children: React.ReactNode;
  unmountOnExit?: boolean;
}) {
  const contentRef = React.useRef<HTMLDivElement>(null);
  const [mounted, setMounted] = React.useState(show);
  const [visible, setVisible] = React.useState(show);

  // Track whether this was open from the very first mount (skip animation)
  const initiallyOpen = React.useRef(show);

  // Mount immediately when show becomes true
  if (show && !mounted) {
    setMounted(true);
    initiallyOpen.current = false; // transitioning open, not initially open
  }

  // After mount renders, trigger the expand
  React.useEffect(() => {
    if (show && mounted && !initiallyOpen.current) {
      // Double rAF: first to ensure DOM is painted with height 0, second to trigger transition
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          setVisible(true);
        });
      });
    }
  }, [show, mounted]);

  // Handle collapse — once collapsed, no longer "initially open"
  React.useEffect(() => {
    if (!show && visible) {
      setVisible(false);
      initiallyOpen.current = false;
    }
  }, [show]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleTransitionEnd = () => {
    if (!show && unmountOnExit) {
      setMounted(false);
    }
  };

  if (!mounted && unmountOnExit) return null;

  // If initially open, render without max-height constraint (no animation needed)
  if (initiallyOpen.current && visible) {
    return (
      <div ref={contentRef}>
        {children}
      </div>
    );
  }

  return (
    <div
      ref={contentRef}
      style={{
        overflow: "hidden",
        transition: "max-height 0.22s ease, opacity 0.22s ease",
        // Animate to an ample fixed height rather than a one-shot
        // scrollHeight read: that measurement is taken from a stale ref
        // (previous commit's DOM) and BEFORE async/dynamically-sized
        // children settle — e.g. the TOTP-setup QR <img> loads from a
        // promise and the manual-entry key renders only once the server
        // secret arrives. A too-small lock + overflow:hidden then clips
        // the QR and the code input. Auth views are far shorter than
        // 2000px, so this never clips and still animates open/closed.
        maxHeight: visible ? "2000px" : "0px",
        opacity: visible ? 1 : 0,
      }}
      onTransitionEnd={handleTransitionEnd}
    >
      {children}
    </div>
  );
}
