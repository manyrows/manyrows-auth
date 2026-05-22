"""Typed response models for the ManyRows server-to-server API.

The API speaks camelCase JSON; these dataclasses expose idiomatic snake_case
attributes. ``from_dict`` maps between the two and tolerates missing/extra keys
(forward-compatible), so a new server field never breaks an older client.
"""

from __future__ import annotations

import dataclasses
import typing
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class User:
    id: str = ""
    email: str = ""
    enabled: bool = False
    email_verified_at: Optional[str] = None
    password_set_at: Optional[str] = None
    totp_enabled: bool = False
    source: str = ""


@dataclass
class UserFieldValue:
    id: str = ""
    user_id: str = ""
    user_field_id: str = ""
    value: Any = None
    updated_at: str = ""
    updated_by: str = ""


@dataclass
class ServerUser:
    """A user with their roles, permissions, and field values in this app."""

    user: User = field(default_factory=User)
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    fields: list[UserFieldValue] = field(default_factory=list)


@dataclass
class Member:
    user_id: str = ""
    email: str = ""
    name: str = ""
    enabled: bool = False
    email_verified_at: Optional[str] = None
    password_set_at: Optional[str] = None
    last_login_at: Optional[str] = None
    source: str = ""
    added_at: str = ""
    roles: list[str] = field(default_factory=list)


@dataclass
class MembersList:
    members: list[Member] = field(default_factory=list)
    total: int = 0
    page: int = 0
    page_size: int = 0


@dataclass
class CheckPermissionResult:
    allowed: bool = False
    permission: str = ""
    account_id: str = ""


@dataclass
class RoleSummary:
    slug: str = ""
    name: str = ""
    permissions: list[str] = field(default_factory=list)


@dataclass
class PermissionSummary:
    slug: str = ""
    name: str = ""


@dataclass
class CreateUserResult:
    user: User = field(default_factory=User)
    created: bool = False
    roles: list[str] = field(default_factory=list)
    invited: bool = False


@dataclass
class BatchUserResult:
    email: str = ""
    user_id: str = ""
    created: bool = False
    error: str = ""


@dataclass
class UserStatus:
    user_id: str = ""
    status: str = ""


@dataclass
class RemoveUserResult:
    removed_from_app: bool = False
    identity_deleted: bool = False


@dataclass
class MagicLinkResult:
    url: str = ""
    expires_at: str = ""


@dataclass
class Session:
    id: str = ""
    created_at: str = ""
    last_seen_at: str = ""
    expires_at: str = ""
    user_agent: str = ""
    ip: str = ""


@dataclass
class AuthLogEntry:
    id: str = ""
    created_at: str = ""
    event: str = ""
    method: str = ""
    outcome: str = ""
    failure_reason: str = ""
    actor_type: str = ""
    ip: str = ""
    user_agent: str = ""
    request_id: str = ""


@dataclass
class AuthLogsPage:
    logs: list[AuthLogEntry] = field(default_factory=list)
    total: int = 0
    page: int = 0
    page_size: int = 0


@dataclass
class Identity:
    provider: str = ""
    provider_subject: str = ""
    provider_email: str = ""
    created_at: str = ""
    last_login_at: str = ""


@dataclass
class Passkey:
    id: str = ""
    name: str = ""
    transports: list[str] = field(default_factory=list)
    created_at: str = ""
    last_used_at: str = ""


@dataclass
class UserField:
    id: str = ""
    user_pool_id: str = ""
    key: str = ""
    value_type: str = ""
    visibility: str = ""
    user_editable: bool = False
    label: str = ""
    status: str = ""
    created_at: str = ""
    updated_at: str = ""
    created_by: str = ""


@dataclass
class DeliveryConfigItem:
    key: str = ""
    type: str = ""
    value: Any = None
    is_set: Optional[bool] = None
    envelope: Any = None


@dataclass
class DeliveryFlagItem:
    key: str = ""
    enabled: bool = False
    role_ids: list[str] = field(default_factory=list)


@dataclass
class DeliveryConfig:
    public: list[DeliveryConfigItem] = field(default_factory=list)
    private: list[DeliveryConfigItem] = field(default_factory=list)
    secrets: list[DeliveryConfigItem] = field(default_factory=list)


@dataclass
class DeliveryFlags:
    client: list[DeliveryFlagItem] = field(default_factory=list)
    server: list[DeliveryFlagItem] = field(default_factory=list)


@dataclass
class Delivery:
    workspace_id: str = ""
    product_id: str = ""
    app_id: str = ""
    updated_at: str = ""
    config: DeliveryConfig = field(default_factory=DeliveryConfig)
    flags: DeliveryFlags = field(default_factory=DeliveryFlags)


def _snake_to_camel(name: str) -> str:
    head, *tail = name.split("_")
    return head + "".join(part[:1].upper() + part[1:] for part in tail)


def _convert(tp: Any, value: Any) -> Any:
    if value is None:
        return None
    origin = typing.get_origin(tp)
    if origin is typing.Union:  # Optional[X]
        args = [a for a in typing.get_args(tp) if a is not type(None)]
        return _convert(args[0], value) if len(args) == 1 else value
    if origin in (list, typing.List):
        (item_tp,) = typing.get_args(tp) or (Any,)
        return [_convert(item_tp, item) for item in value]
    if dataclasses.is_dataclass(tp):
        return from_dict(tp, value)
    return value


T = typing.TypeVar("T")


def from_dict(cls: type[T], data: Optional[dict]) -> T:
    """Build a dataclass from a camelCase JSON dict, ignoring unknown keys."""
    if data is None:
        data = {}
    hints = typing.get_type_hints(cls)
    kwargs = {}
    for f in dataclasses.fields(cls):
        key = _snake_to_camel(f.name)
        if key in data:
            kwargs[f.name] = _convert(hints[f.name], data[key])
    return cls(**kwargs)
