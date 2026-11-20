"""The condition language: a closed, data-only, three-valued predicate language.

A condition is a one-key JSON object (``{"eq": [a, b]}``, ``{"all": [...]}``...).
There is no ``eval``, no regular expression, no arithmetic and no user-defined
operator. ``parse_condition`` validates the shape and the limits; ``evaluate`` is
pure, synchronous and total: it never raises, whatever the attribute values are.

Evaluation is three-valued. A missing attribute or a type mismatch is
``INDETERMINATE``; the decision point turns that into "deny applies" for ``deny``
policies and "not satisfied" for ``require``/``permit`` (fail closed both ways).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from auth_middleware.authz.errors import ConditionError


class Tri(Enum):
    """Truth value of a condition."""

    TRUE = "true"
    FALSE = "false"
    INDETERMINATE = "indeterminate"


class _Absent:
    __slots__ = ()

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


#: The value of an attribute nobody provided.
ABSENT = _Absent()

_PATH_RE = re.compile(r"(subject|resource|action|env)(\.[A-Za-z_][A-Za-z0-9_]*){1,5}")
_MAX_INT = 2**63
_MAX_EVAL_DEPTH = 24

LOGIC_OPS = frozenset({"all", "any"})
COMPARE_OPS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte"})
ORDER_OPS = frozenset({"lt", "lte", "gt", "gte"})
SET_OPS = frozenset({"in", "not_in", "contains", "intersects", "subset"})
STRING_OPS = frozenset({"starts_with", "ends_with"})
BINARY_OPS = COMPARE_OPS | SET_OPS | STRING_OPS
ALL_OPS = LOGIC_OPS | BINARY_OPS | {"not", "exists"}


@dataclass(frozen=True, slots=True)
class ConditionLimits:
    """Bounds enforced when a condition is parsed."""

    max_depth: int = 8
    max_nodes: int = 64
    max_list: int = 100
    max_string: int = 256
    max_path: int = 128


DEFAULT_LIMITS = ConditionLimits()


@dataclass(frozen=True, slots=True)
class Lit:
    """A literal operand (scalar or list of scalars)."""

    value: Any

    def __hash__(self) -> int:
        v = self.value
        return hash(tuple(v) if isinstance(v, list) else v)


@dataclass(frozen=True, slots=True)
class Attr:
    """An attribute operand, e.g. ``subject.attrs.department``."""

    path: str


@dataclass(frozen=True, slots=True)
class Node:
    """An operator and its operands (conditions for ``all``/``any``/``not``)."""

    op: str
    args: tuple[Any, ...]


Condition = Node


def parse_condition(
    raw: Mapping[str, Any], *, limits: ConditionLimits = DEFAULT_LIMITS
) -> Condition:
    """Parse and validate a condition.

    Args:
        raw: The condition as plain data.
        limits: Depth/size bounds.

    Returns:
        The immutable AST.

    Raises:
        ConditionError: Invalid shape or a limit exceeded; ``.pointer`` locates it.
    """
    counter = [0]
    return _parse_condition(raw, "", 1, limits, counter)


def _tick(counter: list[int], limits: ConditionLimits, pointer: str) -> None:
    counter[0] += 1
    if counter[0] > limits.max_nodes:
        raise ConditionError(f"more than {limits.max_nodes} nodes", pointer)


def _parse_condition(
    raw: Any, pointer: str, depth: int, limits: ConditionLimits, counter: list[int]
) -> Node:
    if depth > limits.max_depth:
        raise ConditionError(f"nested deeper than {limits.max_depth}", pointer)
    if not isinstance(raw, Mapping) or len(raw) != 1:
        raise ConditionError(
            "a condition is an object with exactly one operator", pointer
        )
    ((op, arg),) = raw.items()
    if not isinstance(op, str) or op not in ALL_OPS:
        raise ConditionError(f"unknown operator {str(op)[:40]!r}", pointer)
    here = f"{pointer}/{op}"
    _tick(counter, limits, here)
    if op in LOGIC_OPS:
        return _parse_logic(op, arg, here, depth, limits, counter)
    if op == "not":
        return Node(op, (_parse_condition(arg, here, depth + 1, limits, counter),))
    if op == "exists":
        operand = _parse_operand(arg, here, depth + 1, limits, counter, attr_only=True)
        return Node(op, (operand,))
    if not isinstance(arg, (list, tuple)) or len(arg) != 2:
        raise ConditionError(f"{op} needs exactly two operands", here)
    return Node(
        op,
        tuple(
            _parse_operand(a, f"{here}/{i}", depth + 1, limits, counter)
            for i, a in enumerate(arg)
        ),
    )


def _parse_logic(
    op: str,
    arg: Any,
    here: str,
    depth: int,
    limits: ConditionLimits,
    counter: list[int],
) -> Node:
    if not isinstance(arg, (list, tuple)) or not 1 <= len(arg) <= limits.max_list:
        raise ConditionError(f"{op} needs a non-empty list", here)
    return Node(
        op,
        tuple(
            _parse_condition(c, f"{here}/{i}", depth + 1, limits, counter)
            for i, c in enumerate(arg)
        ),
    )


def _scalar(value: Any, pointer: str, limits: ConditionLimits) -> Any:
    kind = type(value)
    if value is None or kind is bool:
        return value
    if kind is int:
        if abs(value) >= _MAX_INT:
            raise ConditionError("integer out of range", pointer)
        return value
    if kind is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ConditionError("NaN and infinity are not allowed", pointer)
        return value
    if kind is str:
        if len(value) > limits.max_string:
            raise ConditionError(f"string longer than {limits.max_string}", pointer)
        return value
    raise ConditionError(f"unsupported literal of type {kind.__name__}", pointer)


def _parse_operand(
    raw: Any,
    pointer: str,
    depth: int,
    limits: ConditionLimits,
    counter: list[int],
    *,
    attr_only: bool = False,
) -> Attr | Lit:
    if depth > limits.max_depth:
        raise ConditionError(f"nested deeper than {limits.max_depth}", pointer)
    _tick(counter, limits, pointer)
    if isinstance(raw, Mapping):
        if set(raw) != {"attr"}:
            raise ConditionError('an operand is a literal or {"attr": path}', pointer)
        path = raw["attr"]
        if (
            not isinstance(path, str)
            or len(path) > limits.max_path
            or not _PATH_RE.fullmatch(path)
        ):
            raise ConditionError("invalid attribute path", pointer)
        return Attr(path)
    if attr_only:
        raise ConditionError('exists needs {"attr": path}', pointer)
    if isinstance(raw, (list, tuple)):
        if len(raw) > limits.max_list:
            raise ConditionError(f"list longer than {limits.max_list}", pointer)
        return Lit([_scalar(v, f"{pointer}/{i}", limits) for i, v in enumerate(raw)])
    return Lit(_scalar(raw, pointer, limits))


def cond_to_dict(cond: Condition) -> dict[str, Any]:
    """Return the plain-data form of a parsed condition (round-trips with parse)."""

    def operand(a: Any) -> Any:
        if isinstance(a, Attr):
            return {"attr": a.path}
        if isinstance(a, Lit):
            return list(a.value) if isinstance(a.value, list) else a.value
        return cond_to_dict(a)

    if cond.op in LOGIC_OPS:
        return {cond.op: [cond_to_dict(c) for c in cond.args]}
    if cond.op == "not":
        return {"not": cond_to_dict(cond.args[0])}
    if cond.op == "exists":
        return {"exists": operand(cond.args[0])}
    return {cond.op: [operand(a) for a in cond.args]}


def condition_paths(cond: Condition) -> frozenset[str]:
    """Return every attribute path the condition reads."""
    found: set[str] = set()
    stack: list[Any] = [cond]
    while stack:
        node = stack.pop()
        if isinstance(node, Attr):
            found.add(node.path)
        elif isinstance(node, Node):
            stack.extend(node.args)
    return frozenset(found)


# ----------------------------------------------------------------- evaluation


def _kind(v: Any) -> str:
    t = type(v)
    if v is None:
        return "null"
    if t is bool:
        return "bool"
    if t in (int, float):
        return "number"
    if t is str:
        return "string"
    if t is datetime:
        return "datetime"
    if t in (list, tuple, set, frozenset):
        return "list"
    return "other"


def _aware(v: datetime) -> bool:
    return v.tzinfo is not None and v.utcoffset() is not None


def _iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _pair(a: Any, b: Any) -> tuple[str, Any, Any] | None:
    """Same-kind operands (coercing an ISO string against a datetime), or ``None``."""
    ka, kb = _kind(a), _kind(b)
    if {ka, kb} == {"datetime", "string"}:
        if ka == "string":
            a, ka = _iso(a), "datetime"
        else:
            b, kb = _iso(b), "datetime"
        if a is None or b is None:
            return None
    if ka != kb or ka in ("list", "other"):
        return None
    if ka == "datetime" and not (_aware(a) and _aware(b)):
        return None
    return ka, a, b


def _eq(a: Any, b: Any) -> Tri:
    pair = _pair(a, b)
    if pair is None:
        return Tri.INDETERMINATE
    return Tri.TRUE if pair[1] == pair[2] else Tri.FALSE


def _order(op: str, a: Any, b: Any) -> Tri:
    pair = _pair(a, b)
    if pair is None or pair[0] not in ("number", "datetime"):
        return Tri.INDETERMINATE
    _, x, y = pair
    result = {"lt": x < y, "lte": x <= y, "gt": x > y, "gte": x >= y}[op]
    return Tri.TRUE if result else Tri.FALSE


def _is_list(v: Any) -> bool:
    return _kind(v) == "list"


def _in(a: Any, s: Any) -> Tri:
    if a is ABSENT or s is ABSENT or not _is_list(s) or _kind(a) in ("list", "other"):
        return Tri.INDETERMINATE
    same_kind = len(s) == 0
    for e in s:
        t = _eq(a, e)
        if t is Tri.TRUE:
            return Tri.TRUE
        if t is Tri.FALSE:
            same_kind = True
    return Tri.FALSE if same_kind else Tri.INDETERMINATE


def _intersects(a: Any, b: Any) -> Tri:
    if not (_is_list(a) and _is_list(b)):
        return Tri.INDETERMINATE
    unknown = False
    for x in a:
        for y in b:
            t = _eq(x, y)
            if t is Tri.TRUE:
                return Tri.TRUE
            unknown = unknown or t is Tri.INDETERMINATE
    return Tri.INDETERMINATE if unknown else Tri.FALSE


def _subset(a: Any, b: Any) -> Tri:
    if not (_is_list(a) and _is_list(b)):
        return Tri.INDETERMINATE
    results = [_in(x, b) for x in a]
    if any(r is Tri.FALSE for r in results):
        return Tri.FALSE
    if any(r is Tri.INDETERMINATE for r in results):
        return Tri.INDETERMINATE
    return Tri.TRUE


def _string_op(op: str, a: Any, b: Any) -> Tri:
    if _kind(a) != "string" or _kind(b) != "string":
        return Tri.INDETERMINATE
    ok = a.startswith(b) if op == "starts_with" else a.endswith(b)
    return Tri.TRUE if ok else Tri.FALSE


def _negate(t: Tri) -> Tri:
    return {
        Tri.TRUE: Tri.FALSE,
        Tri.FALSE: Tri.TRUE,
        Tri.INDETERMINATE: Tri.INDETERMINATE,
    }[t]


def _value(operand: Any, values: Mapping[str, Any]) -> Any:
    if isinstance(operand, Attr):
        return values.get(operand.path, ABSENT)
    return operand.value


def _set_op(op: str, a: Any, b: Any) -> Tri:
    if op == "in":
        return _in(a, b)
    if op == "not_in":
        return _negate(_in(a, b))
    if op == "contains":
        if _kind(a) == "string" and _kind(b) == "string":
            return Tri.TRUE if b in a else Tri.FALSE
        return _in(b, a)
    if op == "intersects":
        return _intersects(a, b)
    return _subset(a, b)


def _binary(op: str, a: Any, b: Any) -> Tri:
    if a is ABSENT or b is ABSENT:
        return Tri.INDETERMINATE
    if op == "eq":
        return _eq(a, b)
    if op == "ne":
        return _negate(_eq(a, b))
    if op in ORDER_OPS:
        return _order(op, a, b)
    if op in SET_OPS:
        return _set_op(op, a, b)
    return _string_op(op, a, b)


def _logic(node: Node, values: Mapping[str, Any], depth: int) -> Tri:
    results = [_walk(c, values, depth + 1) for c in node.args]
    if node.op == "all":
        if Tri.FALSE in results:
            return Tri.FALSE
        return Tri.INDETERMINATE if Tri.INDETERMINATE in results else Tri.TRUE
    if Tri.TRUE in results:
        return Tri.TRUE
    return Tri.INDETERMINATE if Tri.INDETERMINATE in results else Tri.FALSE


def _walk(node: Node, values: Mapping[str, Any], depth: int) -> Tri:
    if depth > _MAX_EVAL_DEPTH:
        return Tri.INDETERMINATE
    op = node.op
    if op in LOGIC_OPS:
        return _logic(node, values, depth)
    if op == "not":
        return _negate(_walk(node.args[0], values, depth + 1))
    if op == "exists":
        value = _value(node.args[0], values)
        return Tri.FALSE if value is ABSENT or value is None else Tri.TRUE
    a, b = (_value(x, values) for x in node.args)
    return _binary(op, a, b)


def evaluate(cond: Condition, values: Mapping[str, Any]) -> Tri:
    """Evaluate ``cond`` over ``values`` (``path -> value``; a missing path is absent).

    Never raises: anything unexpected is ``INDETERMINATE``.
    """
    try:
        return _walk(cond, values, 0)
    except (RecursionError, TypeError, ValueError, OverflowError, AttributeError):
        return Tri.INDETERMINATE


def parse_many(raws: Sequence[Mapping[str, Any]]) -> list[Condition]:
    """Parse several conditions (helper for tools)."""
    return [parse_condition(r) for r in raws]
