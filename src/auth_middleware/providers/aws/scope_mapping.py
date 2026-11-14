"""Explicit mapping of an OAuth2 scope to a group/role name (Cognito M2M tokens)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def names_from_scope(
    claims: Mapping[str, Any],
    *,
    resource_server: str | None,
    scope_map: Mapping[str, str] | None,
) -> list[str]:
    """Map the single custom scope of a token to a name, only if explicitly allowed.

    Cognito client-credentials (machine) tokens carry no ``cognito:groups``; their
    authority is a custom scope ``<resource server>/<scope name>``. Stripping the
    prefix blindly would let a token issued for *another* resource server become a
    group of yours (``other-api/admin`` -> ``admin``), so nothing is mapped unless
    the application says which scopes count.

    Args:
        claims: The token claims.
        resource_server: Identifier of your resource server: only scopes
            ``"<resource_server>/<name>"`` are mapped, to ``<name>``.
        scope_map: Exact ``full scope -> name`` table (takes precedence).

    Returns:
        The mapped name (a one-item list) or ``[]``. A multi-scope claim (a user
        access token: ``openid profile ...``) never maps.
    """
    if not resource_server and not scope_map:
        return []
    scopes = str(claims.get("scope", "")).split()
    if len(scopes) != 1:
        return []
    scope = scopes[0]
    if scope_map and scope in scope_map:
        return [scope_map[scope]]
    if resource_server and scope.startswith(f"{resource_server}/"):
        name = scope[len(resource_server) + 1 :]
        return [name] if name else []
    return []
