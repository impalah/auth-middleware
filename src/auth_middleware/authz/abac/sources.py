"""Policy sources that are not stores: files and compositions."""

from __future__ import annotations

import json
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from loguru import logger

from auth_middleware.authz.abac.types import (
    NewPolicy,
    Policy,
    PolicyStatus,
    new_policy_from_dict,
)
from auth_middleware.authz.errors import ConfigurationError, InvalidPolicyError
from auth_middleware.authz.ports import PolicyStore
from auth_middleware.authz.types import ScopeRef


def _as_policy(item: Policy | NewPolicy | Mapping[str, Any]) -> Policy:
    if isinstance(item, Policy):
        return item
    if isinstance(item, NewPolicy):
        return Policy.from_new(item)
    status = PolicyStatus(item.get("status", "active"))
    return Policy.from_new(new_policy_from_dict(item), status=status)


class StaticPolicySource:
    """Read-only policies from code or a TOML/JSON file (versioned with the app).

    File shapes::

        # JSON
        {"policies": [{"id": "...", "effect": "deny", ...}]}

        # TOML
        [[policies]]
        id = "studio-suspended-readonly"
        effect = "deny"
        permissions = ["*.write"]
        scope = {kind = "studio"}
        condition = {eq = [{attr = "subject.assignment.tenant_status"}, "suspended"]}
    """

    def __init__(self, policies: Iterable[Policy | NewPolicy | Mapping[str, Any]]):
        """
        Raises:
            InvalidPolicyError: A policy is invalid or two share an id.
        """
        found: dict[str, Policy] = {}
        for item in policies:
            policy = _as_policy(item)
            if policy.id in found:
                raise InvalidPolicyError(f"duplicate static policy id: {policy.id}")
            found[policy.id] = policy
        self._policies = tuple(found.values())

    @classmethod
    def from_file(cls, path: str | Path) -> StaticPolicySource:
        """Load a ``.toml`` or ``.json`` file.

        Raises:
            InvalidPolicyError: Unreadable, unsupported or invalid content.
        """
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8")
            if path.suffix == ".toml":
                data = tomllib.loads(text)
            elif path.suffix == ".json":
                data = json.loads(text)
            else:
                raise InvalidPolicyError(f"unsupported policy file type: {path.suffix}")
            items = data["policies"]
            if not isinstance(items, list):
                raise InvalidPolicyError("'policies' must be a list")
            return cls(items)
        except InvalidPolicyError:
            raise
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            raise InvalidPolicyError(f"cannot load policies {path}: {exc}") from exc

    @property
    def policies(self) -> tuple[Policy, ...]:
        """Every policy of the source."""
        return self._policies

    async def list_policies(self, scope: ScopeRef) -> Sequence[Policy]:
        found = [
            p
            for p in self._policies
            if p.status is PolicyStatus.ACTIVE and p.scope.matches(scope)
        ]
        return sorted(found, key=lambda p: (p.priority, p.id))

    async def list_all(self, status: PolicyStatus | None = None) -> Sequence[Policy]:
        return [p for p in self._policies if status in (None, p.status)]


class CompositePolicySource:
    """Several sources read as one. On a clashing id the earlier source wins.

    Call :meth:`verify` at startup (``Authz.install`` does) to fail fast when two
    sources define the same id.
    """

    def __init__(self, *sources: PolicyStore) -> None:
        if not sources:
            raise ConfigurationError("a composite policy source needs sources")
        self.sources = tuple(sources)

    async def list_policies(self, scope: ScopeRef) -> Sequence[Policy]:
        merged: dict[str, Policy] = {}
        for source in self.sources:
            for policy in await source.list_policies(scope):
                if policy.id in merged:
                    logger.warning("policy id {} defined twice: first wins", policy.id)
                    continue
                merged[policy.id] = policy
        return sorted(merged.values(), key=lambda p: (p.priority, p.id))

    async def list_all(self, status: PolicyStatus | None = None) -> Sequence[Policy]:
        found: list[Policy] = []
        for source in self.sources:
            found.extend(await source.list_all(status))
        return found

    async def verify(self) -> None:
        """Raise if two sources define the same policy id.

        Raises:
            ConfigurationError: Naming the clashing ids.
        """
        seen: set[str] = set()
        clashes: set[str] = set()
        for source in self.sources:
            ids = {p.id for p in await source.list_all()}
            clashes |= seen & ids
            seen |= ids
        if clashes:
            raise ConfigurationError(f"policy ids defined twice: {sorted(clashes)}")
