"""Declared attributes: what a policy may read, and of which type."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

ATTRIBUTE_TYPES = frozenset(
    {"string", "int", "float", "bool", "datetime", "string_set"}
)
_PATH_RE = re.compile(r"(subject|resource|action|env)(\.[A-Za-z_][A-Za-z0-9_]*){1,5}")
#: Namespaces whose members must be declared in the catalog (free-form otherwise).
DYNAMIC_PREFIXES = (
    "subject.claims.",
    "subject.assignment.",
    "subject.attrs.",
    "resource.attrs.",
    "env.header.",
)
MAX_ENUM = 100


@dataclass(frozen=True, slots=True)
class AttributeSpec:
    """One attribute.

    Args:
        path: ``namespace.name`` (``subject.attrs.department``).
        type: ``string``, ``int``, ``float``, ``bool``, ``datetime`` or ``string_set``.
        enum: Optional closed set of allowed literal values (string/int only).
        required: Documentation only: a missing value is always INDETERMINATE.
    """

    path: str
    type: str
    enum: tuple[Any, ...] | None = None
    required: bool = False

    def problems(self) -> list[str]:
        """Return what is wrong with this declaration (empty when valid)."""
        found: list[str] = []
        if not _PATH_RE.fullmatch(self.path):
            found.append(f"invalid attribute path: {self.path!r}")
        elif self.path in BUILTIN_ATTRIBUTES:
            found.append(f"{self.path} is a built-in attribute")
        elif not self.path.startswith(DYNAMIC_PREFIXES):
            allowed = ", ".join(DYNAMIC_PREFIXES)
            found.append(f"{self.path}: only members of {allowed} can be declared")
        if self.type not in ATTRIBUTE_TYPES:
            found.append(f"{self.path}: unknown type {self.type!r}")
        if self.enum is not None:
            if self.type not in ("string", "int") or not self.enum:
                found.append(f"{self.path}: enum needs a non-empty string/int type")
            elif len(self.enum) > MAX_ENUM:
                found.append(f"{self.path}: enum longer than {MAX_ENUM}")
        return found


def _b(path: str, type_: str) -> tuple[str, AttributeSpec]:
    return path, AttributeSpec(path, type_)


#: Attributes every deployment has, predeclared.
BUILTIN_ATTRIBUTES: Mapping[str, AttributeSpec] = MappingProxyType(
    dict(
        [
            _b("subject.id", "string"),
            _b("subject.email", "string"),
            _b("subject.groups", "string_set"),
            _b("subject.roles", "string_set"),
            _b("action.permission", "string"),
            _b("resource.kind", "string"),
            _b("resource.id", "string"),
            _b("env.now", "datetime"),
            _b("env.hour_utc", "int"),
            _b("env.weekday", "int"),
            _b("env.method", "string"),
            _b("env.path", "string"),
            _b("env.ip", "string"),
        ]
    )
)


class AttributeSchema:
    """Immutable view of the built-in and the catalog-declared attributes."""

    def __init__(self, declared: Mapping[str, AttributeSpec] | None = None) -> None:
        self._declared = MappingProxyType(dict(declared or {}))

    @property
    def declared(self) -> Mapping[str, AttributeSpec]:
        """The attributes declared by the catalog (without the built-ins)."""
        return self._declared

    def spec(self, path: str) -> AttributeSpec | None:
        """Return the spec of ``path`` or ``None`` when it is not declared.

        A path below a declared one (``subject.attrs.address.city`` when
        ``subject.attrs.address`` is declared) is *not* declared: declare leaves.
        """
        return BUILTIN_ATTRIBUTES.get(path) or self._declared.get(path)

    def __contains__(self, path: object) -> bool:
        return isinstance(path, str) and self.spec(path) is not None
