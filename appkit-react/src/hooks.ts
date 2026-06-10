// appkit-react/hooks.ts — convenience hooks for common data access.
// Implementation lives in ./hooks/* resource modules; this barrel keeps
// every historical import path working.
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
} from "./hooks/snapshot";
export {
  useUpdateProfile,
  useSetPassword,
  useIdentities,
  useDisconnectIdentity,
  useUserFields,
  useUpdateUserFields,
} from "./hooks/account";
export {
  useOrganization,
  useOrganizationList,
  useSetActiveOrganization,
  useCreateOrganization,
  useRenameOrganization,
  useArchiveOrganization,
  useOrganizationMembers,
  useSetOrganizationMember,
  useRemoveOrganizationMember,
  useOrganizationInvites,
  useCreateOrganizationInvite,
  useRevokeOrganizationInvite,
} from "./hooks/organizations";
export { useSessions, useRevokeSession } from "./hooks/sessions";
