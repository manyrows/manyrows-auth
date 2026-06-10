// appkit-react/src/hooks/organizations.ts — self-serve organization hooks.
import { useCallback } from "react";
import { useAppKit } from "../AppKit";
import { authedJson, listQuery } from "./shared";
import type {
  AppKitOrganization,
  AppKitOrganizationInvite,
  AppKitCreatedOrganization,
  AppKitOrgListParams,
  AppKitOrganizationMemberPage,
  AppKitOrganizationInvitePage,
} from "../types";

/**
 * Returns the session's active organization, or null when there is none
 * (a user in no orgs, or an app without organizations enabled).
 *
 * ```tsx
 * const org = useOrganization();
 * if (org) return <p>Acting in {org.name} ({org.orgRole})</p>;
 * ```
 */
export function useOrganization(): AppKitOrganization | null {
  const { snapshot } = useAppKit();
  return snapshot?.appData?.organization ?? null;
}

/**
 * Returns every organization the user belongs to (for a switcher). Empty
 * when the user belongs to none or the app doesn't have organizations enabled.
 *
 * ```tsx
 * const orgs = useOrganizationList();
 * ```
 */
export function useOrganizationList(): AppKitOrganization[] {
  const { snapshot } = useAppKit();
  return snapshot?.appData?.organizations ?? [];
}

/**
 * Returns a function that switches the session's active organization.
 *
 * On success it refreshes the snapshot — switching changes authorization,
 * so roles/permissions/active-org re-resolve for the new org — and resolves
 * with the new active organization. Throws if the user is not an active
 * member of the target org (or orgs aren't enabled for the app).
 *
 * ```tsx
 * const setActiveOrganization = useSetActiveOrganization();
 * await setActiveOrganization(org.id);
 * ```
 */
export function useSetActiveOrganization(): (orgId: string) => Promise<AppKitOrganization> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;

  return useCallback(async (orgId: string) => {
    if (!token || !baseURL) {
      throw new Error("Not authenticated");
    }

    const res = await fetch(`${baseURL}/a/session/organization`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ organizationId: orgId }),
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      throw new Error(errBody?.issues?.[0]?.message || errBody?.error || "Failed to switch organization");
    }

    const body = await res.json().catch(() => ({}));
    // Re-resolve appData (roles/permissions/active org) for the new org.
    refresh();
    return body?.organization as AppKitOrganization;
  }, [token, baseURL, refresh]);
}

// =====================
// Self-serve organization management
// =====================
//
// These wrap the authed /a/organizations/* endpoints. Authorization is
// enforced server-side by the caller's org tier (owner/admin/member); a call
// the user isn't allowed to make rejects with the server's error code.

/**
 * Returns a function to create an organization (self-serve). The app must have
 * `org_creation_policy = self_serve`; otherwise the server rejects with
 * `error.forbidden`. The creator is seeded as the owner. Refreshes the snapshot
 * so the new org appears in `useOrganizationList()`.
 *
 * ```tsx
 * const createOrg = useCreateOrganization();
 * const org = await createOrg({ name: "Acme" });
 * ```
 */
export function useCreateOrganization(): (params: { name: string; slug?: string }) => Promise<AppKitCreatedOrganization> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (params: { name: string; slug?: string }) => {
      const org = (await authedJson(token, baseURL, `/a/organizations`, {
        method: "POST",
        body: JSON.stringify({ name: params.name, slug: params.slug ?? "" }),
      }, "Failed to create organization")) as AppKitCreatedOrganization;
      refresh();
      return org;
    },
    [token, baseURL, refresh],
  );
}

/**
 * Returns a function to rename an organization (owner/admin). Refreshes the
 * snapshot so the new name shows in `useOrganizationList()`.
 */
export function useRenameOrganization(): (orgId: string, params: { name?: string; slug?: string }) => Promise<void> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, params: { name?: string; slug?: string }) => {
      await authedJson(token, baseURL, `/a/organizations/${orgId}`, {
        method: "PATCH",
        body: JSON.stringify(params),
      }, "Failed to rename organization");
      refresh();
    },
    [token, baseURL, refresh],
  );
}

/**
 * Returns a function to archive an organization (owner-only). Reversible
 * operator-side. Refreshes the snapshot.
 */
export function useArchiveOrganization(): (orgId: string) => Promise<void> {
  const { snapshot, refresh } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string) => {
      await authedJson(token, baseURL, `/a/organizations/${orgId}`, { method: "DELETE" }, "Failed to archive organization");
      refresh();
    },
    [token, baseURL, refresh],
  );
}

/**
 * Returns a function that fetches a page of an organization's members (any
 * active member may read), plus the total match count. Not part of the snapshot
 * — call it on demand. pageSize defaults to 50 (capped at 200 server-side).
 *
 * ```tsx
 * const listMembers = useOrganizationMembers();
 * const { members, total } = await listMembers(org.id, { page: 0, search: "jane" });
 * ```
 */
export function useOrganizationMembers(): (
  orgId: string,
  opts?: AppKitOrgListParams,
) => Promise<AppKitOrganizationMemberPage> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, opts?: AppKitOrgListParams) => {
      const body = (await authedJson(token, baseURL, `/a/organizations/${orgId}/members${listQuery(opts)}`,
        { method: "GET" }, "Failed to load members")) as Partial<AppKitOrganizationMemberPage>;
      return {
        members: body?.members ?? [],
        total: body?.total ?? 0,
        page: body?.page ?? 0,
        pageSize: body?.pageSize ?? 0,
      };
    },
    [token, baseURL],
  );
}

/**
 * Returns a function to change a member's tier and/or project roles
 * (owner/admin). Pass either field. Last-owner demotion rejects with
 * `error.conflict`.
 */
export function useSetOrganizationMember(): (
  orgId: string,
  userId: string,
  params: { orgRole?: string; roleIds?: string[] },
) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, userId: string, params: { orgRole?: string; roleIds?: string[] }) => {
      await authedJson(token, baseURL, `/a/organizations/${orgId}/members/${userId}`, {
        method: "PATCH",
        body: JSON.stringify(params),
      }, "Failed to update member");
    },
    [token, baseURL],
  );
}

/**
 * Returns a function to remove a member, or leave the org (pass your own user
 * id). Removing someone else needs owner/admin; the last owner can't be
 * removed (`error.conflict`).
 */
export function useRemoveOrganizationMember(): (orgId: string, userId: string) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, userId: string) => {
      await authedJson(token, baseURL, `/a/organizations/${orgId}/members/${userId}`, { method: "DELETE" },
        "Failed to remove member");
    },
    [token, baseURL],
  );
}

/**
 * Returns a function that fetches a page of an organization's pending invites
 * (owner/admin), plus the total match count. pageSize defaults to 50 (cap 200).
 */
export function useOrganizationInvites(): (
  orgId: string,
  opts?: AppKitOrgListParams,
) => Promise<AppKitOrganizationInvitePage> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, opts?: AppKitOrgListParams) => {
      const body = (await authedJson(token, baseURL, `/a/organizations/${orgId}/invites${listQuery(opts)}`,
        { method: "GET" }, "Failed to load invites")) as Partial<AppKitOrganizationInvitePage>;
      return {
        invites: body?.invites ?? [],
        total: body?.total ?? 0,
        page: body?.page ?? 0,
        pageSize: body?.pageSize ?? 0,
      };
    },
    [token, baseURL],
  );
}

/**
 * Returns a function to invite an email to the organization (owner/admin). The
 * app must have an App URL configured for the accept link.
 */
export function useCreateOrganizationInvite(): (
  orgId: string,
  params: { email: string; orgRole?: string; roleIds?: string[] },
) => Promise<AppKitOrganizationInvite> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, params: { email: string; orgRole?: string; roleIds?: string[] }) => {
      return (await authedJson(token, baseURL, `/a/organizations/${orgId}/invites`, {
        method: "POST",
        body: JSON.stringify(params),
      }, "Failed to send invitation")) as AppKitOrganizationInvite;
    },
    [token, baseURL],
  );
}

/** Returns a function to revoke a pending invite (owner/admin). */
export function useRevokeOrganizationInvite(): (orgId: string, inviteId: string) => Promise<void> {
  const { snapshot } = useAppKit();
  const token = snapshot?.jwtToken;
  const baseURL = snapshot?.appBaseURL;
  return useCallback(
    async (orgId: string, inviteId: string) => {
      await authedJson(token, baseURL, `/a/organizations/${orgId}/invites/${inviteId}`, { method: "DELETE" },
        "Failed to revoke invitation");
    },
    [token, baseURL],
  );
}
