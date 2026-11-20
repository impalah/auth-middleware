"""Tests added after a mutation-testing pass over the condition language.

Boundaries of every limit, exact error pointers/messages, the comparison operators at
equality, datetime coercion in both operand orders, and the evaluator's own depth guard.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from auth_middleware.authz.abac.conditions import (
    ConditionLimits,
    Lit,
    Node,
    Tri,
    evaluate,
    parse_condition,
)
from auth_middleware.authz.errors import ConditionError

T, F, I = Tri.TRUE, Tri.FALSE, Tri.INDETERMINATE  # noqa: E741
A = {"attr": "subject.attrs.a"}
B = {"attr": "subject.attrs.b"}
NOW = {"attr": "env.now"}


def run(raw, values=None):
    return evaluate(parse_condition(raw), values or {})


def error(raw, **limits):
    with pytest.raises(ConditionError) as exc:
        parse_condition(
            raw, limits=ConditionLimits(**limits) if limits else ConditionLimits()
        )
    return exc.value


# ------------------------------------------------------------ limit boundaries


def test_node_limit_boundary_is_exact():
    eq = {"eq": [1, 1]}  # three nodes: the operator and its two operands
    parse_condition(eq, limits=ConditionLimits(max_nodes=3))
    err = error(eq, max_nodes=2)
    assert str(err) == "/eq/1: more than 2 nodes" and err.pointer == "/eq/1"
    sixty_four = {"all": [eq] * 21}  # 1 + 21 * 3 = 64 nodes
    parse_condition(sixty_four)
    error({"all": [eq] * 22})


def test_depth_limit_boundary_is_exact():
    def nots(n, leaf):
        raw = leaf
        for _ in range(n):
            raw = {"not": raw}
        return raw

    # a comparison's operands sit one level below it: 6 nots + eq (depth 7) is the deepest
    parse_condition(nots(6, {"eq": [1, 1]}))
    assert str(error(nots(7, {"eq": [1, 1]}))).endswith("nested deeper than 8")
    parse_condition(nots(6, {"exists": A}))  # exists has a single operand, same rule
    err = error(nots(7, {"exists": A}))
    assert err.pointer.endswith("/exists")
    # a logic node's children sit one level below it too
    parse_condition(
        nots(7, {"all": [{"exists": A}]}), limits=ConditionLimits(max_depth=10)
    )
    error(nots(7, {"all": [{"exists": A}]}), max_depth=9)
    assert error(nots(1, {"eq": [1, 1]}), max_depth=2).pointer == "/not/eq/0"


def test_list_string_path_and_integer_boundaries():
    parse_condition({"in": [A, list(range(100))]})
    assert str(error({"in": [A, list(range(101))]})).endswith("list longer than 100")
    parse_condition({"eq": [A, "x" * 256]})
    assert str(error({"eq": [A, "x" * 257]})).endswith("string longer than 256")
    path = "subject.attrs." + "p" * (128 - len("subject.attrs."))
    assert len(path) == 128
    parse_condition({"eq": [{"attr": path}, 1]})
    assert error({"eq": [{"attr": path + "p"}, 1]}).pointer == "/eq/0"
    parse_condition({"eq": [A, 2**63 - 1]})
    assert str(error({"eq": [A, 2**63]})).endswith("integer out of range")
    parse_condition({"eq": [A, -(2**63 - 1)]})
    assert str(error({"eq": [A, -(2**63)]})).endswith("integer out of range")
    parse_condition(
        {"all": [{"exists": A}] * 100}, limits=ConditionLimits(max_nodes=1000)
    )
    assert str(error({"all": [{"exists": A}] * 101}, max_nodes=1000)).endswith(
        "all needs a non-empty list"
    )


def test_non_finite_numbers_are_rejected_with_their_message():
    for bad in (float("nan"), float("inf"), float("-inf")):
        assert str(error({"eq": [A, bad]})) == "/eq/1: NaN and infinity are not allowed"


# ----------------------------------------------------- exact errors and pointers


def test_error_messages_and_pointers_are_exact():
    assert str(error({"eq": [1, 2], "ne": [1, 2]})) == (
        "/: a condition is an object with exactly one operator"
    )
    assert str(error({"zz": 1})) == "/: unknown operator 'zz'"
    assert (
        error({"all": [{"eq": [1, 1]}, {"not": {"eq": [1]}}]}).pointer
        == "/all/1/not/eq"
    )
    assert str(error({"eq": [1]})) == "/eq: eq needs exactly two operands"
    assert str(error({"all": []})) == "/all: all needs a non-empty list"
    assert str(error({"eq": [{"attr": 5}, 1]})) == "/eq/0: invalid attribute path"
    assert str(error({"eq": [{"x": 1}, 1]})) == (
        '/eq/0: an operand is a literal or {"attr": path}'
    )
    assert str(error({"exists": 5})) == '/exists: exists needs {"attr": path}'
    assert str(error({"eq": [b"x", 1]})) == "/eq/0: unsupported literal of type bytes"


def test_a_long_operator_name_is_truncated_to_forty_characters():
    name = "o" * 100
    assert str(error({name: 1})) == f"/: unknown operator {('o' * 40)!r}"
    assert str(error({7: 1})) == "/: unknown operator '7'"


def test_list_literals_must_hold_scalars_and_logic_needs_conditions():
    assert error({"in": [A, [[1]]]}).pointer == "/in/1/0"
    assert error({"all": [1]}).pointer == "/all/0"
    assert error({"not": 1}).pointer == "/not"
    assert error({"all": {"eq": [1, 1]}}).pointer == "/all"


# ------------------------------------------------ comparison operators at equality


@pytest.mark.parametrize(
    "op,expected",
    [("lt", F), ("lte", T), ("gt", F), ("gte", T)],
)
def test_ordering_at_equality(op, expected):
    assert run({op: [A, 3]}, {"subject.attrs.a": 3}) is expected


@pytest.mark.parametrize(
    "op,below,above",
    [("lt", T, F), ("lte", T, F), ("gt", F, T), ("gte", F, T)],
)
def test_ordering_on_both_sides(op, below, above):
    assert run({op: [A, 3]}, {"subject.attrs.a": 2}) is below
    assert run({op: [A, 3]}, {"subject.attrs.a": 4}) is above


def test_ordering_works_for_floats_and_mixed_numbers():
    assert run({"gte": [A, 2.5]}, {"subject.attrs.a": 2.5}) is T
    assert run({"gt": [A, 2]}, {"subject.attrs.a": 2.5}) is T
    assert run({"gt": [A, 2.5]}, {"subject.attrs.a": 2}) is F


# --------------------------------------------------------------- datetimes


def test_datetimes_compare_in_either_operand_order_and_reject_garbage():
    now = datetime(2026, 6, 1, 12, tzinfo=UTC)
    iso = "2026-01-01T00:00:00+00:00"
    assert run({"gt": [NOW, iso]}, {"env.now": now}) is T
    assert run({"gt": [iso, NOW]}, {"env.now": now}) is F  # literal on the left
    assert run({"lt": [iso, NOW]}, {"env.now": now}) is T
    assert run({"lt": ["garbage", NOW]}, {"env.now": now}) is I
    assert run({"lt": [NOW, "garbage"]}, {"env.now": now}) is I
    assert run({"eq": [NOW, "2026-06-01T12:00:00+00:00"]}, {"env.now": now}) is T
    assert run({"eq": ["2026-06-01T12:00:00+00:00", NOW]}, {"env.now": now}) is T
    # an attribute holding a string is not coerced into a datetime unless it parses
    assert run({"lt": [A, NOW]}, {"subject.attrs.a": "nope", "env.now": now}) is I
    assert run({"lt": [A, NOW]}, {"subject.attrs.a": iso, "env.now": now}) is T
    naive_iso = "2026-01-01T00:00:00"
    assert run({"lt": [naive_iso, NOW]}, {"env.now": now}) is I
    assert run({"lt": [NOW, NOW]}, {"env.now": now}) is F


# ------------------------------------------------------------- set operators


def test_membership_guards():
    assert run({"in": [A, [1]]}, {"subject.attrs.a": [1]}) is I  # a set is not a value
    assert run({"in": [A, [1]]}, {"subject.attrs.a": {"k": 1}}) is I
    assert run({"in": [A, B]}, {"subject.attrs.a": 1, "subject.attrs.b": "xyz"}) is I
    assert run({"in": [A, B]}, {"subject.attrs.a": 1}) is I  # the set is missing
    assert run({"in": [A, B]}, {"subject.attrs.b": [1]}) is I  # the value is missing
    assert run({"in": [A, [1, 2]]}, {"subject.attrs.a": 2}) is T


def test_a_string_is_not_a_set_for_intersects_and_subset():
    values = {"subject.attrs.a": "abc", "subject.attrs.b": ["a", "b"]}
    assert run({"intersects": [A, B]}, values) is I
    assert run({"subset": [A, B]}, values) is I
    assert run({"intersects": [B, A]}, values) is I
    assert run({"subset": [B, A]}, values) is I
    assert (
        run({"intersects": [A, B]}, {"subject.attrs.a": 1, "subject.attrs.b": [1]}) is I
    )


def test_contains_on_strings_and_lists():
    assert run({"contains": [A, "ell"]}, {"subject.attrs.a": "hello"}) is T
    assert run({"contains": [A, "xyz"]}, {"subject.attrs.a": "hello"}) is F
    assert run({"contains": [A, "x"]}, {"subject.attrs.a": ["x", "y"]}) is T
    assert run({"contains": [A, "z"]}, {"subject.attrs.a": ["x", "y"]}) is F
    assert (
        run({"contains": [A, B]}, {"subject.attrs.a": "hello", "subject.attrs.b": 5})
        is I
    )


def test_string_operators_need_two_strings():
    assert run({"starts_with": [A, "he"]}, {"subject.attrs.a": "hello"}) is T
    assert run({"ends_with": [A, "lo"]}, {"subject.attrs.a": "hello"}) is T
    assert run({"starts_with": [A, "lo"]}, {"subject.attrs.a": "hello"}) is F
    assert run({"ends_with": [A, "he"]}, {"subject.attrs.a": "hello"}) is F
    assert (
        run({"starts_with": [A, B]}, {"subject.attrs.a": "hello", "subject.attrs.b": 5})
        is I
    )
    assert (
        run({"starts_with": [A, B]}, {"subject.attrs.a": 5, "subject.attrs.b": "x"})
        is I
    )


def test_any_absent_operand_is_indeterminate_whichever_side():
    assert run({"eq": [A, B]}, {"subject.attrs.a": 1}) is I
    assert run({"eq": [A, B]}, {"subject.attrs.b": 1}) is I
    assert run({"eq": [A, B]}, {"subject.attrs.a": 1, "subject.attrs.b": 1}) is T


# ------------------------------------------------------- evaluator depth guard


def chain(n, leaf):
    node = leaf
    for _ in range(n):
        node = Node("not", (node,))
    return node


def test_the_evaluator_guard_allows_depth_24_and_stops_at_25():
    leaf = Node("exists", (parse_condition({"exists": A}).args[0],))  # FALSE: absent
    assert (
        evaluate(chain(24, leaf), {}) is F
    )  # 24 negations, leaf at depth 24: evaluated
    assert evaluate(chain(25, leaf), {}) is I  # leaf at depth 25: refused


def test_hash_of_literals_depends_on_the_value():
    assert hash(Lit(1)) != hash(Lit(2))
    assert hash(Lit([1, 2])) == hash(Lit([1, 2]))
    assert hash(Lit([1, 2])) != hash(Lit([2, 1]))
    assert hash(Lit("a")) != hash(Lit("b"))
