"""Validation of a policy against the permission catalog and the attribute schema."""

from __future__ import annotations

from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any

from auth_middleware.authz.abac.conditions import (
    COMPARE_OPS,
    LOGIC_OPS,
    ORDER_OPS,
    STRING_OPS,
    Attr,
    Lit,
    Node,
    parse_condition,
)
from auth_middleware.authz.abac.schema import AttributeSchema
from auth_middleware.authz.abac.types import Effect, NewPolicy, Policy
from auth_middleware.authz.catalog import PermissionCatalog
from auth_middleware.authz.errors import ConditionError, InvalidPolicyError
from auth_middleware.authz.types import GLOBAL_KIND

_ATTR_TYPE = {
    "string": "string",
    "int": "number",
    "float": "number",
    "bool": "bool",
    "datetime": "datetime",
    "string_set": "set",
}


def policy_matches_permission(pattern: str, permission: str) -> bool:
    """Whether ``pattern`` (exact name or ``*`` wildcard) matches ``permission``."""
    return fnmatchcase(permission, pattern)


class _Checker:
    def __init__(self, schema: AttributeSchema) -> None:
        self.schema = schema
        self.problems: list[str] = []

    def add(self, where: str, message: str) -> None:
        self.problems.append(f"{where}: {message}")

    def operand(self, node: Any, where: str) -> tuple[str | None, Any]:
        """Return ``(type, spec_or_literal)`` of an operand; records undeclared."""
        if isinstance(node, Attr):
            spec = self.schema.spec(node.path)
            if spec is None:
                self.add(where, f"undeclared attribute {node.path}")
                return None, None
            return _ATTR_TYPE[spec.type], spec
        value = node.value
        if isinstance(value, list):
            return "set", value
        return _literal_type(value), value

    def check(self, node: Node, where: str) -> None:
        if node.op in LOGIC_OPS or node.op == "not":
            for i, child in enumerate(node.args):
                self.check(child, f"{where}/{node.op}/{i}")
            return
        here = f"{where}/{node.op}"
        if node.op == "exists":
            self.operand(node.args[0], here)
            return
        left, right = (self.operand(a, f"{here}/{i}") for i, a in enumerate(node.args))
        if left[0] is None or right[0] is None:
            return
        self._types(node, here, left, right)

    def _types(
        self, node: Node, here: str, left: tuple[Any, Any], right: tuple[Any, Any]
    ) -> None:
        op = node.op
        lt, rt = left[0], right[0]
        if op in COMPARE_OPS:
            self._compare(op, here, node, left, right)
        elif op in STRING_OPS:
            if lt != "string" or rt != "string":
                self.add(here, f"{op} needs two strings")
        elif op in ("in", "not_in"):
            self._member(here, node, left, right)
        elif op == "contains":
            ok = (lt == "set" and rt != "set") or (lt == rt == "string")
            if not ok:
                self.add(here, "contains needs (set, value) or (string, string)")
        elif lt != "set" or rt != "set":
            self.add(here, f"{op} needs two sets")

    def _compare(
        self,
        op: str,
        here: str,
        node: Node,
        left: tuple[Any, Any],
        right: tuple[Any, Any],
    ) -> None:
        (lt, _), (rt, _) = left, right
        if lt == "datetime" and rt == "string" and _is_iso(node.args[1]):
            return
        if lt == "string" and rt == "datetime" and _is_iso(node.args[0]):
            return
        if lt != rt or lt == "set":
            self.add(here, f"{op} compares {lt} with {rt}")
            return
        if op in ORDER_OPS and lt not in ("number", "datetime"):
            self.add(here, f"{op} needs numbers or datetimes, got {lt}")
        self._enum(here, node)

    def _member(
        self, here: str, node: Node, left: tuple[Any, Any], right: tuple[Any, Any]
    ) -> None:
        (lt, _), (rt, rv) = left, right
        if rt != "set" or lt in ("set", "null"):
            self.add(here, f"{node.op} needs (value, set)")
            return
        if isinstance(node.args[1], Lit):
            bad = [v for v in rv if _literal_type(v) != lt]
            if bad:
                self.add(here, f"set items must be of type {lt}")
        elif lt != "string":
            self.add(here, "a string_set attribute holds strings")
        self._enum(here, node)

    def _enum(self, here: str, node: Node) -> None:
        attrs = [a for a in node.args if isinstance(a, Attr)]
        lits = [a for a in node.args if isinstance(a, Lit)]
        for attr in attrs:
            spec = self.schema.spec(attr.path)
            if spec is None or spec.enum is None:
                continue
            for lit in lits:
                values = lit.value if isinstance(lit.value, list) else [lit.value]
                bad = [v for v in values if v not in spec.enum]
                if bad:
                    self.add(here, f"{bad!r} not in the enum of {attr.path}")


def _literal_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def _is_iso(node: Any) -> bool:
    if not isinstance(node, Lit) or not isinstance(node.value, str):
        return False
    try:
        parsed = datetime.fromisoformat(node.value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _check_scope_and_permissions(
    policy: Policy | NewPolicy, catalog: PermissionCatalog, problems: list[str]
) -> None:
    kind = policy.scope.kind
    known = catalog.permissions()
    try:
        catalog.scope_kind(kind)
    except Exception:
        problems.append(f"unknown scope kind: {kind}")
    if kind == GLOBAL_KIND and policy.scope.id not in (None, "*"):
        problems.append("a global policy has no scope id")
    for pattern in policy.permissions:
        matched = [p for p in known if policy_matches_permission(pattern, p)]
        if not matched:
            problems.append(f"permission pattern {pattern!r} matches nothing")
        wrong = sorted(p for p in matched if catalog.spec(p).scope_kind != kind)
        if wrong:
            problems.append(
                f"pattern {pattern!r} spans scope kinds other than {kind}: {wrong}"
            )


def validate_policy(
    policy: Policy | NewPolicy,
    catalog: PermissionCatalog,
    *,
    allow_permit: bool = False,
) -> None:
    """Check a policy against the catalog; report **every** problem at once.

    Args:
        policy: The policy (or the input of a write).
        catalog: Permissions, scope kinds and declared attributes.
        allow_permit: Accept ``permit`` policies (``grant`` mode).

    Raises:
        InvalidPolicyError: With ``.problems`` listing everything wrong.
    """
    problems: list[str] = []
    _check_scope_and_permissions(policy, catalog, problems)
    if policy.effect is Effect.PERMIT and not allow_permit:
        problems.append("permit policies need mode='grant'")
    if policy.hide and policy.effect is Effect.PERMIT:
        problems.append("hide only applies to deny/require policies")
    try:
        cond = parse_condition(policy.condition)
    except ConditionError as exc:
        problems.append(str(exc))
    else:
        checker = _Checker(catalog.attributes)
        checker.check(cond, "")
        problems.extend(checker.problems)
    if problems:
        raise InvalidPolicyError(
            f"invalid policy {policy.id!r}: " + "; ".join(problems), tuple(problems)
        )
