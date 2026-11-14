"""Validated, immutable permission catalog (roles x permissions x scope kinds)."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from loguru import logger

from auth_middleware.authz.errors import CatalogError, UnknownPermissionError
from auth_middleware.authz.types import GLOBAL_KIND

_PERMISSION_RE = re.compile(r"[a-z][a-z0-9_.]*")
_KIND_RE = re.compile(r"[a-z][a-z0-9_]*")


@dataclass(frozen=True, slots=True)
class ScopeKind:
    """A declared kind of scope.

    Args:
        name: Kind name, e.g. ``"studio"`` or ``"global"``.
        hide_existence: ``True``: no assignment -> not visible (404).
            ``False``: no assignment -> denied (403).
    """

    name: str
    hide_existence: bool = True


@dataclass(frozen=True, slots=True)
class PermissionSpec:
    """A permission of the catalog.

    Args:
        name: Permission name, e.g. ``"design.write"``.
        scope_kind: Declared scope kind the permission belongs to.
        sensitive: Metadata for audit and UIs; does not change enforcement.
    """

    name: str
    scope_kind: str
    sensitive: bool = False


class PermissionCatalog:
    """Immutable catalog: ``role -> permissions`` plus permission and scope metadata.

    Build it with :meth:`from_mapping` or :meth:`from_file`. It never reads a
    database: a catalog is code/config versioned with the application.
    """

    def __init__(
        self,
        scopes: Mapping[str, ScopeKind],
        permissions: Mapping[str, PermissionSpec],
        roles: Mapping[str, frozenset[str]],
    ) -> None:
        self._scopes = MappingProxyType(dict(scopes))
        self._permissions = MappingProxyType(dict(permissions))
        self._roles = MappingProxyType(dict(roles))
        granting: dict[str, set[str]] = {name: set() for name in permissions}
        for role, perms in roles.items():
            for perm in perms:
                granting[perm].add(role)
        self._granting = MappingProxyType(
            {k: frozenset(v) for k, v in granting.items()}
        )

    @classmethod
    def from_mapping(
        cls,
        *,
        scopes: Sequence[ScopeKind],
        permissions: Sequence[PermissionSpec],
        roles: Mapping[str, Iterable[str]],
    ) -> PermissionCatalog:
        """Build and validate a catalog.

        ``StrEnum`` members are accepted wherever a name is expected.

        Args:
            scopes: Declared scope kinds.
            permissions: Declared permissions.
            roles: ``role -> permission names``.

        Returns:
            The immutable catalog.

        Raises:
            CatalogError: Listing *all* problems found.
        """
        problems: list[str] = []
        scope_map = cls._check_scopes(scopes, problems)
        perm_map = cls._check_permissions(permissions, scope_map, problems)
        role_map = cls._check_roles(roles, perm_map, problems)

        if problems:
            raise CatalogError("; ".join(problems))
        return cls(scope_map, perm_map, role_map)

    @staticmethod
    def _check_scopes(
        scopes: Sequence[ScopeKind], problems: list[str]
    ) -> dict[str, ScopeKind]:
        scope_map: dict[str, ScopeKind] = {}
        for sk in scopes:
            name = str(sk.name)
            if not _KIND_RE.fullmatch(name):
                problems.append(f"invalid scope kind name: {name!r}")
            elif name in scope_map:
                problems.append(f"duplicate scope kind: {name}")
            scope_map[name] = ScopeKind(name, sk.hide_existence)
        return scope_map

    @staticmethod
    def _check_permissions(
        permissions: Sequence[PermissionSpec],
        scope_map: Mapping[str, ScopeKind],
        problems: list[str],
    ) -> dict[str, PermissionSpec]:
        perm_map: dict[str, PermissionSpec] = {}
        for spec in permissions:
            pname = str(spec.name)
            kind = str(spec.scope_kind)
            if not pname:
                problems.append("empty permission name")
                continue
            if not _PERMISSION_RE.fullmatch(pname):
                problems.append(f"invalid permission name: {pname!r}")
            if pname in perm_map:
                problems.append(f"duplicate permission: {pname}")
            if kind not in scope_map:
                problems.append(f"permission {pname} uses undeclared scope kind {kind}")
            perm_map[pname] = PermissionSpec(pname, kind, spec.sensitive)
        return perm_map

    @staticmethod
    def _check_roles(
        roles: Mapping[str, Iterable[str]],
        perm_map: Mapping[str, PermissionSpec],
        problems: list[str],
    ) -> dict[str, frozenset[str]]:
        role_map: dict[str, frozenset[str]] = {}
        for role, perms in roles.items():
            rname = str(role)
            names = frozenset(str(p) for p in perms)
            if not rname:
                problems.append("empty role name")
                continue
            for p in sorted(names):
                if p not in perm_map:
                    problems.append(f"role {rname} grants undeclared permission {p}")
            if not names:
                logger.debug("role {} has no permissions", rname)
            role_map[rname] = names
        return role_map

    @classmethod
    def from_file(cls, path: Path) -> PermissionCatalog:
        """Load a catalog from a TOML (``.toml``) or JSON (``.json``) file.

        Shape::

            [[scopes]]
            name = "studio"
            hide_existence = true

            [[permissions]]
            name = "design.write"
            scope = "studio"
            sensitive = false

            [roles]
            TIT = ["design.write"]

        Raises:
            CatalogError: Unreadable file, unknown extension or invalid content.
        """
        path = Path(path)
        try:
            if path.suffix == ".toml":
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            elif path.suffix == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
            else:
                raise CatalogError(f"unsupported catalog file type: {path.suffix}")
            return cls.from_mapping(
                scopes=[
                    ScopeKind(s["name"], s.get("hide_existence", True))
                    for s in data.get("scopes", [])
                ],
                permissions=[
                    PermissionSpec(p["name"], p["scope"], p.get("sensitive", False))
                    for p in data.get("permissions", [])
                ],
                roles=data.get("roles", {}),
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise CatalogError(f"cannot load catalog {path}: {exc}") from exc

    def permissions_for(self, role: str) -> frozenset[str]:
        """Return the permissions granted by ``role``.

        Raises:
            CatalogError: Unknown role.
        """
        try:
            return self._roles[str(role)]
        except KeyError:
            raise CatalogError(f"unknown role: {role}") from None

    def roles(self) -> frozenset[str]:
        """Return all role names."""
        return frozenset(self._roles)

    def permissions(self) -> frozenset[str]:
        """Return all permission names."""
        return frozenset(self._permissions)

    def spec(self, permission: str) -> PermissionSpec:
        """Return the spec of ``permission``.

        Raises:
            UnknownPermissionError: Not in the catalog.
        """
        try:
            return self._permissions[str(permission)]
        except KeyError:
            raise UnknownPermissionError(f"unknown permission: {permission}") from None

    def scope_kind(self, name: str) -> ScopeKind:
        """Return the declared scope kind ``name``.

        Raises:
            CatalogError: Undeclared kind.
        """
        try:
            return self._scopes[str(name)]
        except KeyError:
            raise CatalogError(f"unknown scope kind: {name}") from None

    def roles_granting(self, permission: str) -> frozenset[str]:
        """Return the roles that grant ``permission``.

        Raises:
            UnknownPermissionError: Not in the catalog.
        """
        self.spec(permission)
        return self._granting[str(permission)]

    def to_mapping(self) -> dict[str, Any]:
        """Return a plain dict; ``from_mapping(**...)`` of it rebuilds the catalog."""
        return {
            "scopes": [
                ScopeKind(s.name, s.hide_existence) for s in self._scopes.values()
            ],
            "permissions": list(self._permissions.values()),
            "roles": {r: sorted(p) for r, p in self._roles.items()},
        }


__all__ = ["GLOBAL_KIND", "PermissionCatalog", "PermissionSpec", "ScopeKind"]
