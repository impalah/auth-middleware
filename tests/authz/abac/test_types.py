"""AUTHZ-023: ABAC vocabulary."""

from __future__ import annotations

import subprocess
import sys

import pytest

from auth_middleware.authz import ScopeRef
from auth_middleware.authz.abac.types import (
    Effect,
    EntityRef,
    NewPolicy,
    Policy,
    PolicyScope,
    PolicyStatus,
    new_policy_from_dict,
    validate_attributes,
)
from auth_middleware.authz.errors import InvalidPolicyError

COND = {"eq": [{"attr": "subject.id"}, "x"]}


def _new(**kw):
    base = dict(
        id="p1",
        effect=Effect.DENY,
        permissions=("design.write",),
        scope=PolicyScope("studio"),
        condition=COND,
    )
    base.update(kw)
    return NewPolicy(**base)


def test_round_trip_and_hash():
    p = Policy.from_new(_new(hide=True, priority=3, description="d"), revision=2)
    again = Policy.from_dict(p.to_dict())
    assert again == p and hash(again) == hash(p)
    assert p.to_new() == _new(hide=True, priority=3, description="d")


@pytest.mark.parametrize(
    "kw",
    [
        {"id": "Bad Id"},
        {"id": ""},
        {"permissions": ()},
        {"permissions": ("UPPER",)},
        {"permissions": tuple(f"p{i}" for i in range(51))},
        {"description": "x" * 501},
        {"priority": True},
        {"condition": {"eq": [float("nan"), 1]}},
        {"condition": {"x": "y" * 20000}},
        {"effect": "deny"},
    ],
)
def test_invalid_policy_fields(kw):
    with pytest.raises(InvalidPolicyError):
        _new(**kw)


def test_policy_scope():
    assert PolicyScope("studio").matches(ScopeRef("studio", "a"))
    assert PolicyScope("studio", "a").matches(ScopeRef("studio", "a"))
    assert not PolicyScope("studio", "a").matches(ScopeRef("studio", "b"))
    assert not PolicyScope("studio").matches(ScopeRef("company", "a"))
    assert PolicyScope("global").matches(ScopeRef.GLOBAL)
    with pytest.raises(InvalidPolicyError):
        PolicyScope("studio", "*")
    with pytest.raises(InvalidPolicyError):
        PolicyScope("Bad")


def test_from_dict_rejects_unknown_and_missing():
    with pytest.raises(InvalidPolicyError):
        new_policy_from_dict({"id": "a"})
    d = Policy.from_new(_new()).to_dict()
    d["surprise"] = 1
    with pytest.raises(InvalidPolicyError):
        Policy.from_dict(d)
    d.pop("surprise")
    d["effect"] = "maybe"
    with pytest.raises(InvalidPolicyError):
        Policy.from_dict(d)
    with pytest.raises(InvalidPolicyError):
        new_policy_from_dict("nope")  # type: ignore[arg-type]


def test_fail_closed_policy_denies_everything():
    p = Policy.fail_closed("Bad Id!", PolicyScope("studio"))
    assert p.effect is Effect.DENY and p.permissions == ("*",)
    assert p.id == "invalid-policy" and p.status is PolicyStatus.ACTIVE


def test_attributes_validation():
    assert validate_attributes({"a": 1, "b": [1, "x"], "c": {"d": None}}) == {
        "a": 1,
        "b": [1, "x"],
        "c": {"d": None},
    }
    for bad in (
        {"a b": 1},
        {"a": object()},
        {"a": float("nan")},
        {"a": list(range(101))},
        {"a": {"b": {"c": {"d": 1}}}},
        {"a": "x" * 5000},
        {1: 2},
    ):
        with pytest.raises(InvalidPolicyError):
            validate_attributes(bad)  # type: ignore[arg-type]
    with pytest.raises(InvalidPolicyError):
        validate_attributes([1])  # type: ignore[arg-type]


def test_entity_ref():
    assert EntityRef.principal("u1") == EntityRef("principal", "principal", "u1")
    for args in (("other", "k", "i"), ("resource", "Bad", "i"), ("resource", "k", "")):
        with pytest.raises(InvalidPolicyError):
            EntityRef(*args)  # type: ignore[arg-type]


def test_authz_import_does_not_load_abac_engine():
    code = (
        "import sys, auth_middleware.authz as a;"
        "bad=[m for m in sys.modules if m.startswith('auth_middleware.authz.abac.')"
        " and m.split('.')[-1] in ('pdp','conditions','attributes','service','cache')];"
        "print(bad)"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "[]"
