"""Dependency-free vocabulary of the ABAC subsystem (policies and attributes)."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from auth_middleware.authz.errors import InvalidPolicyError
from auth_middleware.authz.types import GLOBAL_KIND, MAX_ID_LENGTH, ScopeRef

POLICY_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,99}")
PATTERN_RE = re.compile(r"[a-z0-9_.*]{1,100}")
_KIND_RE = re.compile(r"[a-z][a-z0-9_]*")
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")

MAX_PERMISSIONS = 50
MAX_DESCRIPTION = 500
MAX_POLICY_BYTES = 16 * 1024
MAX_ATTRIBUTES_BYTES = 4096
MAX_ATTRIBUTE_LIST = 100
MAX_ATTRIBUTE_DEPTH = 3
MAX_ENTITY_ID_LENGTH = 500


class Effect(StrEnum):
    """What a policy does when its condition holds."""

    DENY = "deny"
    REQUIRE = "require"
    PERMIT = "permit"


class PolicyStatus(StrEnum):
    """Lifecycle status of a policy (a disabled policy is kept as history)."""

    ACTIVE = "active"
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class PolicyScope:
    """Where a policy applies: one scope, or every scope of a kind (``id=None``)."""

    kind: str
    id: str | None = None

    def __post_init__(self) -> None:
        if not _KIND_RE.fullmatch(self.kind):
            raise InvalidPolicyError(f"invalid policy scope kind: {self.kind!r}")
        if self.id is not None:
            if not self.id or len(self.id) > MAX_ID_LENGTH:
                raise InvalidPolicyError("invalid policy scope id")
            if self.id == "*" and self.kind != GLOBAL_KIND:
                raise InvalidPolicyError("'*' is only valid for the global scope")

    def matches(self, scope: ScopeRef) -> bool:
        """Whether a policy with this scope applies to ``scope``."""
        return self.kind == scope.kind and self.id in (None, scope.id)


def _check_permissions(permissions: tuple[str, ...]) -> None:
    if not permissions or len(permissions) > MAX_PERMISSIONS:
        raise InvalidPolicyError(f"a policy needs 1..{MAX_PERMISSIONS} permissions")
    for p in permissions:
        if not isinstance(p, str) or not PATTERN_RE.fullmatch(p):
            raise InvalidPolicyError(f"invalid permission pattern: {p!r}")


def _check_condition(condition: Mapping[str, Any]) -> None:
    if not isinstance(condition, Mapping):
        raise InvalidPolicyError("condition must be an object")
    try:
        size = len(json.dumps(condition, allow_nan=False, sort_keys=True))
    except (TypeError, ValueError, RecursionError):
        raise InvalidPolicyError("condition is not valid JSON data") from None
    if size > MAX_POLICY_BYTES:
        raise InvalidPolicyError(f"condition larger than {MAX_POLICY_BYTES} bytes")


def _check_fields(
    policy_id: str,
    effect: Effect,
    permissions: tuple[str, ...],
    condition: Mapping[str, Any],
    description: str,
    priority: int,
) -> None:
    if not POLICY_ID_RE.fullmatch(policy_id):
        raise InvalidPolicyError(f"invalid policy id: {policy_id!r}")
    if not isinstance(effect, Effect):
        raise InvalidPolicyError(f"invalid effect: {effect!r}")
    _check_permissions(permissions)
    if len(description) > MAX_DESCRIPTION:
        raise InvalidPolicyError("description too long")
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise InvalidPolicyError("priority must be an integer")
    _check_condition(condition)


@dataclass(frozen=True, slots=True)
class NewPolicy:
    """Input of ``PolicyAdmin.create`` / ``replace``.

    Args:
        id: Human-chosen id, ``[a-z0-9][a-z0-9_.-]{0,99}``, unique across the store.
        effect: ``deny``, ``require`` or ``permit``.
        permissions: Exact names or ``*`` patterns (``design.*``, ``*.write``).
        scope: Where it applies.
        condition: The raw condition AST (parsed by ``parse_condition``).
        description: Free text (<= 500 characters).
        priority: Lower is evaluated first.
        hide: A denial answers "not visible" (404) instead of 403.
        enforce: ``False`` is shadow mode: evaluated and reported, never enforced.
    """

    id: str
    effect: Effect
    permissions: tuple[str, ...]
    scope: PolicyScope
    condition: Mapping[str, Any]
    description: str = ""
    priority: int = 0
    hide: bool = False
    enforce: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "permissions", tuple(self.permissions))
        _check_fields(
            self.id,
            self.effect,
            self.permissions,
            self.condition,
            self.description,
            self.priority,
        )

    def __hash__(self) -> int:
        return hash((self.id, self.effect, self.permissions, self.scope))


@dataclass(frozen=True, slots=True)
class Policy:
    """A stored policy: a :class:`NewPolicy` plus status, revision and timestamps."""

    id: str
    effect: Effect
    permissions: tuple[str, ...]
    scope: PolicyScope
    condition: Mapping[str, Any]
    description: str = ""
    priority: int = 0
    hide: bool = False
    enforce: bool = True
    status: PolicyStatus = PolicyStatus.ACTIVE
    revision: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "permissions", tuple(self.permissions))
        _check_fields(
            self.id,
            self.effect,
            self.permissions,
            self.condition,
            self.description,
            self.priority,
        )

    def __hash__(self) -> int:
        return hash((self.id, self.revision, self.status))

    @classmethod
    def from_new(
        cls,
        new: NewPolicy,
        *,
        status: PolicyStatus = PolicyStatus.ACTIVE,
        revision: int = 0,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> Policy:
        """Build a stored policy from a :class:`NewPolicy`."""
        return cls(
            new.id,
            new.effect,
            new.permissions,
            new.scope,
            dict(new.condition),
            new.description,
            new.priority,
            new.hide,
            new.enforce,
            status,
            revision,
            created_at,
            updated_at,
        )

    @classmethod
    def fail_closed(
        cls, policy_id: str, scope: PolicyScope, permissions: tuple[str, ...] = ("*",)
    ) -> Policy:
        """A ``deny`` that always applies (stands in for an undecodable policy)."""
        safe_id = policy_id if POLICY_ID_RE.fullmatch(policy_id) else "invalid-policy"
        return cls(
            safe_id,
            Effect.DENY,
            permissions,
            scope,
            {"exists": {"attr": "action.permission"}},
            "undecodable stored policy: denies (fail closed)",
        )

    def to_new(self) -> NewPolicy:
        """Return the writable part."""
        return NewPolicy(
            self.id,
            self.effect,
            self.permissions,
            self.scope,
            self.condition,
            self.description,
            self.priority,
            self.hide,
            self.enforce,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict (round-trips through :meth:`from_dict`)."""
        return {
            "id": self.id,
            "effect": self.effect.value,
            "permissions": list(self.permissions),
            "scope": {"kind": self.scope.kind, "id": self.scope.id},
            "condition": dict(self.condition),
            "description": self.description,
            "priority": self.priority,
            "hide": self.hide,
            "enforce": self.enforce,
            "status": self.status.value,
            "revision": self.revision,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Policy:
        """Rebuild a policy from :meth:`to_dict` (or a hand-written document).

        Raises:
            InvalidPolicyError: Missing/invalid fields.
        """
        new = new_policy_from_dict(data)
        try:
            status = PolicyStatus(data.get("status", "active"))
            revision = int(data.get("revision", 0))
            created = _opt_dt(data.get("created_at"))
            updated = _opt_dt(data.get("updated_at"))
        except (ValueError, TypeError) as exc:
            raise InvalidPolicyError(f"invalid policy document: {exc}") from None
        return cls.from_new(
            new,
            status=status,
            revision=revision,
            created_at=created,
            updated_at=updated,
        )


def _opt_dt(value: Any) -> datetime | None:
    return None if value in (None, "") else datetime.fromisoformat(str(value))


def new_policy_from_dict(data: Mapping[str, Any]) -> NewPolicy:
    """Build a :class:`NewPolicy` from a plain document (JSON/TOML).

    Raises:
        InvalidPolicyError: Missing/invalid fields or unknown keys.
    """
    if not isinstance(data, Mapping):
        raise InvalidPolicyError("a policy must be an object")
    allowed = {
        "id",
        "effect",
        "permissions",
        "scope",
        "condition",
        "description",
        "priority",
        "hide",
        "enforce",
        "status",
        "revision",
        "created_at",
        "updated_at",
    }
    extra = sorted(set(data) - allowed)
    if extra:
        raise InvalidPolicyError(f"unknown policy fields: {extra}")
    try:
        scope = data["scope"]
        if not isinstance(scope, Mapping):
            raise InvalidPolicyError("scope must be an object")
        raw_perms = data["permissions"]
        if isinstance(raw_perms, str) or not isinstance(raw_perms, (list, tuple)):
            raise InvalidPolicyError("permissions must be a list")
        hide, enforce = data.get("hide", False), data.get("enforce", True)
        if not isinstance(hide, bool) or not isinstance(enforce, bool):
            raise InvalidPolicyError("hide and enforce must be booleans")
        return NewPolicy(
            id=str(data["id"]),
            effect=Effect(data["effect"]),
            permissions=tuple(raw_perms),
            scope=PolicyScope(str(scope["kind"]), scope.get("id")),
            condition=data["condition"],
            description=str(data.get("description", "")),
            priority=data.get("priority", 0),
            hide=hide,
            enforce=enforce,
        )
    except KeyError as exc:
        raise InvalidPolicyError(f"missing policy field: {exc.args[0]}") from None
    except ValueError as exc:
        if isinstance(exc, InvalidPolicyError):
            raise
        raise InvalidPolicyError(f"invalid policy document: {exc}") from None


@dataclass(frozen=True, slots=True)
class EntityRef:
    """The owner of persisted attributes: a principal or a resource."""

    namespace: Literal["principal", "resource"]
    kind: str
    id: str

    def __post_init__(self) -> None:
        if self.namespace not in ("principal", "resource"):
            raise InvalidPolicyError(f"invalid namespace: {self.namespace!r}")
        if not _KIND_RE.fullmatch(self.kind):
            raise InvalidPolicyError(f"invalid entity kind: {self.kind!r}")
        if not self.id or len(self.id) > MAX_ENTITY_ID_LENGTH:
            raise InvalidPolicyError("invalid entity id")

    @classmethod
    def principal(cls, principal_id: str) -> EntityRef:
        """Reference to a principal (kind is always ``principal``)."""
        return cls("principal", "principal", principal_id)


def _check_float(value: float) -> float:
    if value != value or value in (float("inf"), float("-inf")):
        raise InvalidPolicyError("NaN and infinity are not allowed")
    return value


def _check_value(value: Any, depth: int) -> Any:
    kind = type(value)
    if value is None or kind in (bool, int, str):
        return value
    if isinstance(value, str):
        # A str subclass could override comparison: keep an exact copy.
        return str.__getitem__(value, slice(None))
    if kind is float:
        return _check_float(value)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ATTRIBUTE_LIST:
            raise InvalidPolicyError("attribute list too long")
        return [_check_value(v, depth) for v in value]
    if isinstance(value, Mapping):
        if depth >= MAX_ATTRIBUTE_DEPTH:
            raise InvalidPolicyError("attribute map nested too deeply")
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str) or not _KEY_RE.fullmatch(k):
                raise InvalidPolicyError(f"invalid attribute name: {k!r}")
            out[k] = _check_value(v, depth + 1)
        return out
    raise InvalidPolicyError(f"unsupported attribute value type: {kind}")


def validate_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Check and copy an attribute map.

    Values are JSON scalars, lists of scalars (<= 100) or nested maps (depth <= 3);
    keys are identifiers; the whole map is at most 4 KB.

    Raises:
        InvalidPolicyError: Anything else.
    """
    if not isinstance(attributes, Mapping):
        raise InvalidPolicyError("attributes must be an object")
    try:
        copy = _check_value(attributes, 0)
        size = len(json.dumps(copy, allow_nan=False))
    except RecursionError:
        raise InvalidPolicyError("attribute map nested too deeply") from None
    if size > MAX_ATTRIBUTES_BYTES:
        raise InvalidPolicyError(f"attributes larger than {MAX_ATTRIBUTES_BYTES} bytes")
    return dict(copy)


@dataclass(frozen=True, slots=True)
class EntityAttributes:
    """Persisted attributes of one entity, with an optimistic ``revision``."""

    ref: EntityRef
    attributes: Mapping[str, Any] = field(default_factory=dict)
    revision: int = 0

    def __hash__(self) -> int:
        return hash((self.ref, self.revision))
