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
  AppKitOrganization,
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
  useOrganization,
  useOrganizationList,
  useSetActiveOrganization,
} from "./hooks";
