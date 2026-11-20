"""AUTHZ-024: condition language."""

from __future__ import annotations

import pathlib
import time
from datetime import UTC, datetime

import pytest

from auth_middleware.authz.abac.conditions import (
    ABSENT,
    ConditionLimits,
    Tri,
    cond_to_dict,
    condition_paths,
    evaluate,
    parse_condition,
)
from auth_middleware.authz.errors import ConditionError

T, F, I = Tri.TRUE, Tri.FALSE, Tri.INDETERMINATE  # noqa: E741
A = {"attr": "subject.attrs.a"}
B = {"attr": "subject.attrs.b"}


def ev(raw, **values):
    return evaluate(
        parse_condition(raw), {k.replace("__", "."): v for k, v in values.items()}
    )


def run(raw, values):
    return evaluate(parse_condition(raw), values)


@pytest.mark.parametrize(
    "raw,values,expected",
    [
        ({"eq": [A, 1]}, {"subject.attrs.a": 1}, T),
        ({"eq": [A, 1]}, {"subject.attrs.a": 2}, F),
        ({"eq": [A, 1]}, {}, I),
        ({"eq": [A, 1]}, {"subject.attrs.a": "1"}, I),
        ({"eq": [A, 1.0]}, {"subject.attrs.a": 1}, T),
        ({"eq": [A, True]}, {"subject.attrs.a": 1}, I),
        ({"eq": [True, 1]}, {}, I),
        ({"eq": [A, None]}, {"subject.attrs.a": None}, T),
        ({"ne": [A, "x"]}, {"subject.attrs.a": "y"}, T),
        ({"ne": [A, "x"]}, {"subject.attrs.a": "x"}, F),
        ({"ne": [A, "x"]}, {}, I),
        ({"lt": [A, 3]}, {"subject.attrs.a": 2}, T),
        ({"lt": [A, 3]}, {"subject.attrs.a": 3}, F),
        ({"lte": [A, 3]}, {"subject.attrs.a": 3}, T),
        ({"gt": [A, 3]}, {"subject.attrs.a": 4}, T),
        ({"gte": [A, 3]}, {"subject.attrs.a": 2}, F),
        ({"lt": [A, 3]}, {"subject.attrs.a": "2"}, I),
        ({"lt": ["a", "b"]}, {}, I),
        ({"lt": [True, False]}, {}, I),
        ({"in": [A, [1, 2]]}, {"subject.attrs.a": 2}, T),
        ({"in": [A, [1, 2]]}, {"subject.attrs.a": 3}, F),
        ({"in": [A, ["x"]]}, {"subject.attrs.a": 3}, I),
        ({"in": [A, []]}, {"subject.attrs.a": 3}, F),
        ({"in": [A, B]}, {"subject.attrs.a": 1, "subject.attrs.b": 1}, I),
        ({"in": [A, B]}, {"subject.attrs.a": 1, "subject.attrs.b": [1]}, T),
        ({"not_in": [A, [1]]}, {"subject.attrs.a": 2}, T),
        ({"not_in": [A, [1]]}, {"subject.attrs.a": 1}, F),
        ({"not_in": [A, [1]]}, {}, I),
        ({"contains": [A, "x"]}, {"subject.attrs.a": ["x", "y"]}, T),
        ({"contains": [A, "z"]}, {"subject.attrs.a": ["x", "y"]}, F),
        ({"contains": [A, "ell"]}, {"subject.attrs.a": "hello"}, T),
        ({"contains": [A, "z"]}, {"subject.attrs.a": 5}, I),
        (
            {"intersects": [A, B]},
            {"subject.attrs.a": [1, 2], "subject.attrs.b": [2]},
            T,
        ),
        ({"intersects": [A, B]}, {"subject.attrs.a": [1], "subject.attrs.b": [2]}, F),
        ({"intersects": [A, B]}, {"subject.attrs.a": [], "subject.attrs.b": [2]}, F),
        ({"intersects": [A, B]}, {"subject.attrs.a": [1], "subject.attrs.b": ["x"]}, I),
        ({"subset": [A, B]}, {"subject.attrs.a": [1], "subject.attrs.b": [1, 2]}, T),
        ({"subset": [A, B]}, {"subject.attrs.a": [3], "subject.attrs.b": [1, 2]}, F),
        ({"subset": [A, B]}, {"subject.attrs.a": [], "subject.attrs.b": [1]}, T),
        ({"subset": [A, B]}, {"subject.attrs.a": 1, "subject.attrs.b": [1]}, I),
        ({"starts_with": [A, "ab"]}, {"subject.attrs.a": "abc"}, T),
        ({"starts_with": [A, "bc"]}, {"subject.attrs.a": "abc"}, F),
        ({"ends_with": [A, "bc"]}, {"subject.attrs.a": "abc"}, T),
        ({"ends_with": [A, "bc"]}, {"subject.attrs.a": 3}, I),
        ({"exists": A}, {"subject.attrs.a": 0}, T),
        ({"exists": A}, {}, F),
        ({"exists": A}, {"subject.attrs.a": None}, F),
        ({"not": {"eq": [A, 1]}}, {"subject.attrs.a": 2}, T),
        ({"not": {"eq": [A, 1]}}, {}, I),
        (
            {"all": [{"eq": [A, 1]}, {"eq": [B, 1]}]},
            {"subject.attrs.a": 1, "subject.attrs.b": 1},
            T,
        ),
        ({"all": [{"eq": [A, 1]}, {"eq": [B, 1]}]}, {"subject.attrs.a": 2}, F),
        ({"all": [{"eq": [A, 1]}, {"eq": [B, 1]}]}, {"subject.attrs.a": 1}, I),
        ({"any": [{"eq": [A, 1]}, {"eq": [B, 1]}]}, {"subject.attrs.a": 1}, T),
        ({"any": [{"eq": [A, 1]}, {"eq": [B, 1]}]}, {"subject.attrs.a": 2}, I),
        (
            {"any": [{"eq": [A, 1]}, {"eq": [B, 1]}]},
            {"subject.attrs.a": 2, "subject.attrs.b": 2},
            F,
        ),
    ],
)
def test_truth_table(raw, values, expected):
    assert run(raw, values) is expected


def test_datetime_semantics():
    now = datetime(2026, 1, 1, 12, tzinfo=UTC)
    NOW = {"attr": "env.now"}
    assert run({"gte": [NOW, "2026-01-01T00:00:00+00:00"]}, {"env.now": now}) is T
    assert run({"lt": [NOW, "2026-01-01T00:00:00+00:00"]}, {"env.now": now}) is F
    assert run({"lt": [NOW, "2026-01-01T13:00:00+01:00"]}, {"env.now": now}) is F
    assert run({"lt": [NOW, "garbage"]}, {"env.now": now}) is I
    assert (
        run({"lt": [NOW, "2026-01-01T00:00:00"]}, {"env.now": now}) is I
    )  # naive literal
    naive = datetime(2026, 1, 1)
    assert run({"lt": [NOW, "2027-01-01T00:00:00+00:00"]}, {"env.now": naive}) is I


def test_round_trip_and_paths():
    raw = {"all": [{"eq": [A, 1]}, {"not": {"in": [B, [1, "x", None]]}}, {"exists": A}]}
    cond = parse_condition(raw)
    assert cond_to_dict(cond) == raw
    assert parse_condition(cond_to_dict(cond)) == cond
    assert condition_paths(cond) == {"subject.attrs.a", "subject.attrs.b"}
    assert hash(cond) == hash(parse_condition(raw))


@pytest.mark.parametrize(
    "raw,pointer",
    [
        ("nope", ""),
        ({}, ""),
        ({"eq": [1, 2], "ne": [1, 2]}, ""),
        ({"bogus": [1, 2]}, ""),
        ({"eq": [1]}, "/eq"),
        ({"eq": [1, 2, 3]}, "/eq"),
        ({"eq": "ab"}, "/eq"),
        ({"all": []}, "/all"),
        ({"all": {"eq": [1, 1]}}, "/all"),
        ({"all": [{"eq": [1, 1]}, {"zz": 1}]}, "/all/1"),
        ({"eq": [{"attr": "__class__"}, 1]}, "/eq/0"),
        ({"eq": [{"attr": "subject"}, 1]}, "/eq/0"),
        ({"eq": [{"attr": "other.x"}, 1]}, "/eq/0"),
        ({"eq": [{"attr": 5}, 1]}, "/eq/0"),
        ({"eq": [{"attr": "subject.a", "x": 1}, 1]}, "/eq/0"),
        ({"eq": [{"$where": "1"}, 1]}, "/eq/0"),
        ({"eq": [{"eq": [1, 1]}, 1]}, "/eq/0"),
        ({"eq": [[[1]], 1]}, "/eq/0/0"),
        ({"eq": [float("nan"), 1]}, "/eq/0"),
        ({"eq": [float("inf"), 1]}, "/eq/0"),
        ({"eq": [10**30, 1]}, "/eq/0"),
        ({"eq": [b"x", 1]}, "/eq/0"),
        ({"eq": ["x" * 257, 1]}, "/eq/0"),
        ({"eq": [list(range(101)), 1]}, "/eq/0"),
        ({"exists": 5}, "/exists"),
        ({"exists": {"attr": "subject.x"}, "eq": [1, 1]}, ""),
        ({1: [1, 1]}, ""),
    ],
)
def test_invalid_conditions(raw, pointer):
    with pytest.raises(ConditionError) as exc:
        parse_condition(raw)
    assert exc.value.pointer == pointer


def test_limits():
    deep = {"eq": [1, 1]}
    for _ in range(8):
        deep = {"not": deep}
    with pytest.raises(ConditionError):
        parse_condition(deep)  # depth 9
    ok = {"eq": [1, 1]}
    for _ in range(6):
        ok = {"not": ok}
    parse_condition(ok)
    wide = {"all": [{"eq": [1, 1]} for _ in range(30)]}  # 1 + 30*3 nodes
    with pytest.raises(ConditionError):
        parse_condition(wide)
    parse_condition(wide, limits=ConditionLimits(max_nodes=200))
    huge = {"not": {"not": {"not": {}}}}
    with pytest.raises(ConditionError):
        parse_condition(huge)


def test_ten_thousand_deep_nesting_is_cut_at_the_limit():
    raw: dict = {"eq": [1, 1]}
    for _ in range(10_000):
        raw = {"not": raw}
    with pytest.raises(ConditionError):
        parse_condition(raw)


def test_evaluation_never_raises_on_hostile_values():
    class Evil(str):
        def __eq__(self, other):  # pragma: no cover - must never be called
            raise AssertionError("called")

        __hash__ = str.__hash__

    class Obj:
        def __eq__(self, other):  # pragma: no cover
            raise AssertionError("called")

    cond = parse_condition(
        {
            "any": [
                {"eq": [A, "x"]},
                {"in": [A, ["x"]]},
                {"lt": [A, 1]},
                {"subset": [A, B]},
            ]
        }
    )
    for v in (Evil("x"), Obj(), {"k": 1}, b"x", 10**400, float("nan"), object, [Obj()]):
        assert evaluate(cond, {"subject.attrs.a": v, "subject.attrs.b": v}) in Tri


def test_evaluate_is_fast():
    raw = {"all": [{"eq": [A, i]} for i in range(15)]}
    cond = parse_condition(raw)
    start = time.perf_counter()
    for _ in range(100):
        evaluate(cond, {"subject.attrs.a": 1})
    assert (time.perf_counter() - start) / 100 < 0.001


def test_absent_sentinel():
    assert repr(ABSENT) == "ABSENT" and not ABSENT


def test_module_has_no_eval_exec_or_regex_use():
    src = pathlib.Path("src/auth_middleware/authz/abac/conditions.py").read_text()
    body = "\n".join(
        line for line in src.splitlines() if not line.lstrip().startswith(("#", '"'))
    )
    for needle in ("eval(", "exec(", "re.match", "re.search", "re.sub"):
        assert needle not in body, needle
    # the only regex is the fixed attribute-path grammar, never user supplied
    assert body.count("re.compile") == 1
