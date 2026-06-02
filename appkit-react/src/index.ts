export { AppKit, useAppKit, AppKitAuthed, type AppKitTheme, type AppKitProps } from "./AppKit";
export { useTheme, type ColorTokens, type ColorMode, type ThemeContextValue } from "./theme";
export type {
  ManyRowsAppKitError,
  ManyRowsAppKitErrorCode,
  ManyRowsAppKitReady,
  ManyRowsAppKitHandle,
  ManyRowsAppKitSnapshot,
  AppKitAccount,
  AppKitAppData,
  AppKitFeatureFlag,
  AppKitConfigValue,
} from "./types";

// Convenience hooks
export {
  useUser,
  useRoles,
  usePermissions,
  usePermission,
  useRole,
  useFeatureFlags,
  useFeatureFlag,
  useConfig,
  useConfigValue,
  useToken,
  useAuthFetch,
  useUpdateProfile,
  useSetPassword,
} from "./hooks";
