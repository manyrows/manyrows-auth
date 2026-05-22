# manyrows-server (Python)

Typed Python client for the ManyRows **server-to-server API** — call it from
your backend to manage and authorize users. Standard library only, no
dependencies; Python 3.9+.

```bash
pip install manyrows-server
```

## Usage

```python
import os
from manyrows import ManyRowsServer, ManyRowsServerError

mr = ManyRowsServer(
    base_url="https://auth.example.com",
    workspace="acme",
    app_id="3f2a1c8e-…",
    api_key=os.environ["MANYROWS_API_KEY"],  # mr_<prefix>_<secret>
)

# Authorize an action
if mr.check_permission(user_id, "posts:read").allowed:
    ...

# Provision a user and grant a role (idempotent)
result = mr.create_user(email="alice@example.com", email_verified=True, roles=["editor"])

# Suspend, then re-enable
mr.set_user_status(result.user.id, "disabled")
mr.set_user_status(result.user.id, "active")

# Passwordless onboarding link (requires magic-link auth on the app)
link = mr.create_magic_link(result.user.id)
print(link.url)
```

Responses are typed dataclasses with idiomatic snake_case attributes
(`user.email_verified_at`). Every call is scoped to the one app and to its
**members** — the user pool only shares credentials across apps, it is not an
access boundary.

## Errors

Non-2xx responses raise `ManyRowsServerError`, carrying the HTTP `status` and
the API's stable error `code`:

```python
try:
    mr.get_user(user_id)
except ManyRowsServerError as err:
    if err.status == 404:
        ...  # not a member of this app
```

## API

| Method | Endpoint |
| --- | --- |
| `get_delivery()` | `GET /` |
| `check_permission(user_id, permission)` | `GET /check-permission` |
| `list_roles()` / `list_permissions()` | `GET /roles` · `/permissions` |
| `list_users(search=…, page=…, page_size=…)` | `GET /users` |
| `get_user_by_email(email)` / `get_user(user_id)` | `GET /users` |
| `create_user(email=…, email_verified=…, roles=…)` | `POST /users` |
| `set_user_status(user_id, "active" / "disabled")` | `PATCH /users/{id}` |
| `remove_user(user_id)` | `DELETE /users/{id}` |
| `replace_user_roles(user_id, roles)` | `PUT /users/{id}/roles` |
| `get_user_permissions(user_id)` / `set_user_permissions(user_id, perms)` | `GET` · `PUT /users/{id}/permissions` |
| `revoke_user_sessions(user_id)` | `DELETE /users/{id}/sessions` |
| `list_user_sessions(user_id)` / `revoke_user_session(user_id, session_id)` | `GET` · `DELETE /users/{id}/sessions[/{sid}]` |
| `set_user_password(user_id, password)` / `clear_user_password(user_id)` | `PUT` · `DELETE /users/{id}/password` |
| `create_magic_link(user_id, remember_me=…)` | `POST /users/{id}/magic-link` |
| `get_user_auth_logs(user_id, page=…, page_size=…)` | `GET /users/{id}/auth-logs` |
| `list_user_fields()` | `GET /user-fields` |
| `get_user_field_values(user_id)` | `GET /user-fields/users/{id}` |
| `set_user_field_value(field_id, user_id, value)` | `PUT /user-fields/{fieldId}/users/{id}` |
| `delete_user_field_value(field_id, user_id)` | `DELETE /user-fields/{fieldId}/users/{id}` |

The full HTTP contract is in [`docs/server-api.openapi.yaml`](../docs/server-api.openapi.yaml).

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## License

MIT
