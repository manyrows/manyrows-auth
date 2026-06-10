// Friendly messages for the #mr_invite_error=<code> fragment the server
// appends when an org-invite acceptance fails (server: AcceptOrgInvite).
// Unknown codes get the generic message.
export function inviteErrorMessage(code: string): string {
  switch (code) {
    case "invite_expired":
      return "This invitation has expired — ask for a new one.";
    case "invite_revoked":
      return "This invitation was revoked.";
    case "invalid_token":
      return "This invitation link is invalid.";
    case "account_disabled":
      return "Your account is disabled.";
    default:
      return "Something went wrong accepting the invitation — please try again.";
  }
}

// extractInviteError pulls mr_invite_error out of a location hash, returning
// the code (or "") and the hash with ONLY that pair removed — any other
// fragment params (session tokens etc.) survive untouched.
export function extractInviteError(hash: string): { code: string; rest: string } {
  const raw = hash.startsWith("#") ? hash.slice(1) : hash;
  if (!raw) return { code: "", rest: hash };
  const params = new URLSearchParams(raw);
  const code = params.get("mr_invite_error") ?? "";
  if (code === "") return { code: "", rest: hash };
  params.delete("mr_invite_error");
  const rest = params.toString();
  return { code, rest: rest ? "#" + rest : "" };
}
