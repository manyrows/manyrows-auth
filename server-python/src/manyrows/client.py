"""Client for the ManyRows server-to-server API."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from .models import (
    CheckPermissionResult,
    CreateUserResult,
    Delivery,
    MagicLinkResult,
    MembersList,
    PermissionSummary,
    RemoveUserResult,
    RoleSummary,
    AuthLogsPage,
    BatchUserResult,
    ServerUser,
    Session,
    UserField,
    UserFieldValue,
    UserStatus,
    from_dict,
)


class ManyRowsServerError(Exception):
    """Raised for any non-2xx response; carries the HTTP status and error code."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message or code or f"HTTP {status}")
        self.status = status
        self.code = code
        self.message = message or code


class ManyRowsServer:
    """Typed client for one app's server-to-server API.

    >>> mr = ManyRowsServer(
    ...     base_url="https://auth.example.com",
    ...     workspace="acme",
    ...     app_id="3f2a…",
    ...     api_key=os.environ["MANYROWS_API_KEY"],
    ... )
    >>> mr.check_permission(user_id, "posts:read").allowed
    """

    def __init__(
        self,
        *,
        base_url: str,
        workspace: str,
        app_id: str,
        api_key: str,
        timeout: float = 30.0,
    ):
        if not base_url:
            raise ValueError("ManyRowsServer: base_url is required")
        if not workspace:
            raise ValueError("ManyRowsServer: workspace is required")
        if not app_id:
            raise ValueError("ManyRowsServer: app_id is required")
        if not api_key:
            raise ValueError("ManyRowsServer: api_key is required")

        root = base_url.rstrip("/")
        ws = urllib.parse.quote(workspace, safe="")
        app = urllib.parse.quote(app_id, safe="")
        self._base = f"{root}/x/{ws}/api/v1/apps/{app}"
        self._api_key = api_key
        self._timeout = timeout

    # ---- Delivery ----

    def get_delivery(self) -> Delivery:
        """All config values and feature flags for the app."""
        return from_dict(Delivery, self._request("GET", "/"))

    # ---- Authorization ----

    def check_permission(self, user_id: str, permission: str) -> CheckPermissionResult:
        """Whether a member has a permission in this app."""
        data = self._request("GET", "/check-permission", query={"accountId": user_id, "permission": permission})
        return from_dict(CheckPermissionResult, data)

    def list_roles(self) -> list[RoleSummary]:
        """The product's roles, each with the permission slugs it grants."""
        data = self._request("GET", "/roles")
        return [from_dict(RoleSummary, r) for r in data.get("roles", [])]

    def list_permissions(self) -> list[PermissionSummary]:
        """The product's permissions."""
        data = self._request("GET", "/permissions")
        return [from_dict(PermissionSummary, p) for p in data.get("permissions", [])]

    # ---- Users ----

    def list_users(
        self, *, search: Optional[str] = None, page: Optional[int] = None, page_size: Optional[int] = None
    ) -> MembersList:
        """List the app's members (``search`` is an email substring filter)."""
        query: dict[str, Any] = {}
        if search:
            query["search"] = search
        if page:
            query["page"] = page
        if page_size:
            query["pageSize"] = page_size
        return from_dict(MembersList, self._request("GET", "/users", query=query))

    def get_user_by_email(self, email: str) -> ServerUser:
        """Look up a member by exact email."""
        return from_dict(ServerUser, self._request("GET", "/users", query={"email": email}))

    def get_user(self, user_id: str) -> ServerUser:
        """Fetch a member by id."""
        return from_dict(ServerUser, self._request("GET", f"/users/{urllib.parse.quote(user_id, safe='')}"))

    def create_user(
        self, *, email: str, email_verified: bool = False, roles: Optional[list[str]] = None
    ) -> CreateUserResult:
        """Provision a user: create-or-find by email in the pool and add to the app. Idempotent."""
        body: dict[str, Any] = {"email": email}
        if email_verified:
            body["emailVerified"] = True
        if roles is not None:
            body["roles"] = roles
        return from_dict(CreateUserResult, self._request("POST", "/users", body=body))

    def batch_create_users(
        self, emails: list[str], *, email_verified: bool = False, roles: Optional[list[str]] = None
    ) -> list[BatchUserResult]:
        """Provision up to 100 users at once, all with the same optional roles.

        Each email is reported independently, so one bad email doesn't sink the
        rest. Idempotent per email.
        """
        body: dict[str, Any] = {"emails": emails}
        if email_verified:
            body["emailVerified"] = True
        if roles is not None:
            body["roles"] = roles
        data = self._request("POST", "/users:batch", body=body)
        return [from_dict(BatchUserResult, item) for item in data.get("results", [])]

    def set_user_status(self, user_id: str, status: str) -> UserStatus:
        """Suspend (``"disabled"``) or re-enable (``"active"``) a member in this app."""
        data = self._request("PATCH", f"/users/{urllib.parse.quote(user_id, safe='')}", body={"status": status})
        return from_dict(UserStatus, data)

    def remove_user(self, user_id: str) -> RemoveUserResult:
        """Remove a member from the app; prunes the pool identity if left in no other app."""
        return from_dict(RemoveUserResult, self._request("DELETE", f"/users/{urllib.parse.quote(user_id, safe='')}"))

    def replace_user_roles(self, user_id: str, roles: list[str]) -> list[str]:
        """Replace a member's roles (full set of slugs; ``[]`` clears them and revokes sessions)."""
        data = self._request(
            "PUT", f"/users/{urllib.parse.quote(user_id, safe='')}/roles", body={"roles": roles}
        )
        return data.get("roles", [])

    def get_user_permissions(self, user_id: str) -> list[str]:
        """A member's direct permission overrides (slugs), separate from role-granted ones."""
        data = self._request("GET", f"/users/{urllib.parse.quote(user_id, safe='')}/permissions")
        return data.get("permissions", [])

    def set_user_permissions(self, user_id: str, permissions: list[str]) -> list[str]:
        """Replace a member's direct permission overrides (full set of slugs). Returns the result."""
        data = self._request(
            "PUT", f"/users/{urllib.parse.quote(user_id, safe='')}/permissions", body={"permissions": permissions}
        )
        return data.get("permissions", [])

    def get_user_auth_logs(self, user_id: str, *, page: Optional[int] = None, page_size: Optional[int] = None) -> AuthLogsPage:
        """A member's authentication-event history for this app (newest first, paginated)."""
        query: dict[str, Any] = {}
        if page:
            query["page"] = page
        if page_size:
            query["pageSize"] = page_size
        data = self._request("GET", f"/users/{urllib.parse.quote(user_id, safe='')}/auth-logs", query=query)
        return from_dict(AuthLogsPage, data)

    def revoke_user_sessions(self, user_id: str) -> int:
        """Force-logout: revoke all of a member's sessions for this app. Returns the count revoked."""
        data = self._request("DELETE", f"/users/{urllib.parse.quote(user_id, safe='')}/sessions")
        return data.get("revoked", 0)

    def list_user_sessions(self, user_id: str) -> list[Session]:
        """A member's active sessions for this app."""
        data = self._request("GET", f"/users/{urllib.parse.quote(user_id, safe='')}/sessions")
        return [from_dict(Session, s) for s in data.get("sessions", [])]

    def revoke_user_session(self, user_id: str, session_id: str) -> None:
        """Revoke a single session of a member."""
        path = f"/users/{urllib.parse.quote(user_id, safe='')}/sessions/{urllib.parse.quote(session_id, safe='')}"
        self._request("DELETE", path)

    def set_user_password(self, user_id: str, password: str) -> None:
        """Set or replace a member's password (enforced against the app's policy)."""
        self._request("PUT", f"/users/{urllib.parse.quote(user_id, safe='')}/password", body={"password": password})

    def clear_user_password(self, user_id: str) -> None:
        """Clear a member's password (email+password sign-in disabled until a new one is set)."""
        self._request("DELETE", f"/users/{urllib.parse.quote(user_id, safe='')}/password")

    def set_user_email_verified(self, user_id: str, verified: bool) -> None:
        """Mark a member's email verified or unverified (a pool-level attribute)."""
        self._request(
            "PUT", f"/users/{urllib.parse.quote(user_id, safe='')}/email-verified", body={"verified": verified}
        )

    def create_magic_link(self, user_id: str, *, remember_me: bool = False) -> MagicLinkResult:
        """Generate a one-time passwordless sign-in link (requires magic-link auth on the app)."""
        data = self._request(
            "POST", f"/users/{urllib.parse.quote(user_id, safe='')}/magic-link", body={"rememberMe": remember_me}
        )
        return from_dict(MagicLinkResult, data)

    # ---- User fields ----

    def list_user_fields(self) -> list[UserField]:
        """The pool's user-field definitions."""
        data = self._request("GET", "/user-fields")
        return [from_dict(UserField, f) for f in data.get("userFields", [])]

    def get_user_field_values(self, user_id: str) -> list[UserFieldValue]:
        """A member's field values."""
        data = self._request("GET", f"/user-fields/users/{urllib.parse.quote(user_id, safe='')}")
        return [from_dict(UserFieldValue, v) for v in data.get("values", [])]

    def set_user_field_value(self, field_id: str, user_id: str, value: Any) -> UserFieldValue:
        """Set a member's value for a field (validated server-side against the field's type)."""
        path = f"/user-fields/{urllib.parse.quote(field_id, safe='')}/users/{urllib.parse.quote(user_id, safe='')}"
        data = self._request("PUT", path, body={"value": value})
        return from_dict(UserFieldValue, data.get("value"))

    def delete_user_field_value(self, field_id: str, user_id: str) -> None:
        """Clear a member's value for a field."""
        path = f"/user-fields/{urllib.parse.quote(field_id, safe='')}/users/{urllib.parse.quote(user_id, safe='')}"
        self._request("DELETE", path)

    def set_config_value(self, config_key: str, value: Any) -> None:
        """Set this app's value for a public/private config key (read back via get_delivery)."""
        self._request("PUT", f"/config/{urllib.parse.quote(config_key, safe='')}", body={"value": value})

    def delete_config_value(self, config_key: str) -> None:
        """Clear this app's value for a config key."""
        self._request("DELETE", f"/config/{urllib.parse.quote(config_key, safe='')}")

    def set_feature_flag(self, flag_key: str, enabled: bool, roles: Optional[list[str]] = None) -> None:
        """Set this app's feature-flag override, optionally targeting role slugs."""
        body: dict[str, Any] = {"enabled": enabled}
        if roles is not None:
            body["roles"] = roles
        self._request("PUT", f"/features/{urllib.parse.quote(flag_key, safe='')}", body=body)

    def delete_feature_flag(self, flag_key: str) -> None:
        """Clear this app's feature-flag override (falls back to the flag's default)."""
        self._request("DELETE", f"/features/{urllib.parse.quote(flag_key, safe='')}")

    # ---- internal ----

    def _request(
        self, method: str, path: str, *, query: Optional[dict] = None, body: Optional[Any] = None
    ) -> Any:
        url = self._base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)

        data: Optional[bytes] = None
        headers = {"X-API-Key": self._api_key, "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as res:
                raw = res.read()
                if res.status == 204 or not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as err:
            code = f"http_{err.code}"
            message = err.reason or ""
            try:
                parsed = json.loads(err.read())
                code = parsed.get("error", code)
                message = parsed.get("message", message)
            except (ValueError, OSError):
                pass
            raise ManyRowsServerError(err.code, code, message) from None
