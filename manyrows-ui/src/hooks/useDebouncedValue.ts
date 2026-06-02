import * as React from "react";

// useDebouncedValue returns a copy of `value` that only updates after
// `delayMs` of quiescence. Used by the paged list screens (Sessions,
// AuthLogs, ...) to debounce search/filter inputs before refetching.
export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = React.useState(value);
  React.useEffect(() => {
    const t = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(t);
  }, [value, delayMs]);
  return debounced;
}
