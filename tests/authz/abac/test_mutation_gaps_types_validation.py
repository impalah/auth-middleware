"""Tests added after a mutation-testing pass over the ABAC types and the validation.

Every size limit at and just over its boundary, the defaults of ``from_dict``, the exact
fields of ``fail_closed``, hashing, and the exact location/message of each validation
problem.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from auth_middleware.authz.abac.types import (
    Effect,
    EntityAttributes,
    EntityRef,
    NewPolicy,
    Policy,
    PolicyScope,
    PolicyStatus,
    new_policy_from_dict,
    validate_attributes,
)
from auth_middleware.authz.abac.validation import validate_policy
from auth_middleware.authz.errors import InvalidPolicyError

COND = {"eq": [{"attr": "subject.id"}, "x"]}


def np(**kw):
    base = dict(
        id="p1",
        effect=Effect.DENY,
        permissions=("design.write",),
        scope=PolicyScope("studio"),
        condition=COND,
    )
    base.update(kw)
    return NewPolicy(**base)


def doc(**kw):
    base = {
        "id": "p1",
        "effect": "deny",
        "permissions": ["design.write"],
        "scope": {"kind": "studio"},
        "condition": COND,
    }
    base.update(kw)
    return base


# ------------------------------------------------------------ size boundaries


def test_scope_and_entity_id_boundaries():
    PolicyScope("studio", "x" * 200)
    with pytest.raises(InvalidPolicyError):
        PolicyScope("studio", "x" * 201)
    with pytest.raises(InvalidPolicyError):
        PolicyScope("studio", "")  # empty is invalid, not "short"
    EntityRef("resource", "design", "x" * 500)
    with pytest.raises(InvalidPolicyError):
        EntityRef("resource", "design", "x" * 501)
    assert "global scope" in str(_raises(lambda: PolicyScope("studio", "*")))
    PolicyScope("global", "*")


def _raises(fn):
    with pytest.raises(InvalidPolicyError) as exc:
        fn()
    return exc.value


def test_permission_description_and_document_boundaries():
    np(permissions=tuple(f"a.p{i}" for i in range(50)))
    assert _raises(
        lambda: np(permissions=tuple(f"a.p{i}" for i in range(51)))
    ).args == ("a policy needs 1..50 permissions",)
    np(description="d" * 500)
    assert str(_raises(lambda: np(description="d" * 501))) == "description too long"
    # a document of exactly 16 KB is accepted, one byte more is not
    overhead = len(json.dumps({"eq": [""]}, sort_keys=True))
    exact = {"eq": ["x" * (16 * 1024 - overhead)]}
    np(condition=exact)
    err = _raises(lambda: np(condition={"eq": ["x" * (16 * 1024 - overhead + 1)]}))
    assert str(err) == "condition larger than 16384 bytes"
    assert str(_raises(lambda: np(condition={"a": float("nan")}))) == (
        "condition is not valid JSON data"
    )


def test_attribute_boundaries_and_messages():
    assert validate_attributes({"a": list(range(100))})["a"] == list(range(100))
    assert str(_raises(lambda: validate_attributes({"a": list(range(101))}))) == (
        "attribute list too long"
    )
    # maps nest up to three levels (the top-level map is level 0)
    assert validate_attributes({"a": {"b": {"c": 1}}}) == {"a": {"b": {"c": 1}}}
    assert str(_raises(lambda: validate_attributes({"a": {"b": {"c": {"d": 1}}}}))) == (
        "attribute map nested too deeply"
    )
    # a map inside a list counts at the level of the list
    assert validate_attributes({"a": [{"b": 1}]}) == {"a": [{"b": 1}]}
    deep = {"a": [{"b": {"c": {"d": 1}}}]}
    assert (
        str(_raises(lambda: validate_attributes(deep)))
        == "attribute map nested too deeply"
    )
    padding = 4096 - len(json.dumps({"a": ""}))
    assert (
        len(validate_attributes({"a": "x" * padding})["a"]) == padding
    )  # exactly 4 KB
    assert "larger than 4096 bytes" in str(
        _raises(lambda: validate_attributes({"a": "x" * (padding + 1)}))
    )
    for bad in (float("nan"), float("inf"), float("-inf")):
        assert str(_raises(lambda b=bad: validate_attributes({"a": b}))) == (
            "NaN and infinity are not allowed"
        )
    assert validate_attributes({"a": 1.5, "b": -1.5})["b"] == -1.5
    assert str(_raises(lambda: validate_attributes({"a": object()}))).startswith(
        "unsupported attribute value type"
    )
    assert str(_raises(lambda: validate_attributes({"bad key": 1}))) == (
        "invalid attribute name: 'bad key'"
    )


def test_a_str_subclass_is_copied_to_an_exact_str():
    class Evil(str):
        pass

    out = validate_attributes({"a": Evil("x"), "b": [Evil("y")]})
    assert type(out["a"]) is str and type(out["b"][0]) is str


# ----------------------------------------------------- from_dict and defaults


def test_new_policy_defaults_and_rejections():
    new = new_policy_from_dict(doc())
    assert (new.hide, new.enforce, new.priority, new.description) == (
        False,
        True,
        0,
        "",
    )
    full = new_policy_from_dict(
        doc(hide=True, enforce=False, priority=7, description="d")
    )
    assert (full.hide, full.enforce, full.priority, full.description) == (
        True,
        False,
        7,
        "d",
    )
    for bad in (5, None, {"a": 1}):
        assert str(_raises(lambda b=bad: new_policy_from_dict(doc(permissions=b)))) == (
            "permissions must be a list"
        )
    assert str(
        _raises(lambda: new_policy_from_dict(doc(permissions="design.write")))
    ) == ("permissions must be a list")
    assert str(_raises(lambda: new_policy_from_dict(doc(hide="yes")))) == (
        "hide and enforce must be booleans"
    )
    assert str(_raises(lambda: new_policy_from_dict(doc(scope="studio")))) == (
        "scope must be an object"
    )
    assert "missing policy field: condition" in str(
        _raises(
            lambda: new_policy_from_dict(
                {k: v for k, v in doc().items() if k != "condition"}
            )
        )
    )
    assert "unknown policy fields: ['surprise']" in str(
        _raises(lambda: new_policy_from_dict(doc(surprise=1)))
    )


def test_policy_from_dict_defaults_and_timestamps_round_trip():
    minimal = Policy.from_dict(doc())  # no status/revision/timestamps in the document
    assert minimal.status is PolicyStatus.ACTIVE and minimal.revision == 0
    assert minimal.created_at is None and minimal.updated_at is None
    created = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    updated = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
    stored = Policy.from_new(
        np(),
        status=PolicyStatus.DISABLED,
        revision=4,
        created_at=created,
        updated_at=updated,
    )
    data = stored.to_dict()
    assert data["scope"] == {"kind": "studio", "id": None}
    assert (
        data["created_at"] == created.isoformat()
        and data["updated_at"] == updated.isoformat()
    )
    back = Policy.from_dict(data)
    assert back == stored and back.created_at == created and back.updated_at == updated
    assert back.status is PolicyStatus.DISABLED and back.revision == 4
    assert Policy.from_new(np()).to_dict()["created_at"] is None
    assert Policy.from_dict(doc(created_at="")).created_at is None
    for bad in ({"status": "paused"}, {"revision": "x"}, {"created_at": "yesterday"}):
        _raises(lambda b=bad: Policy.from_dict(doc(**b)))
    assert Policy.from_dict(doc(scope={"kind": "studio", "id": "s1"})).scope.id == "s1"


def test_fail_closed_policy_fields():
    scope = PolicyScope("studio", "s1")
    p = Policy.fail_closed("my-policy", scope, ("design.write",))
    assert (
        p.id == "my-policy" and p.scope == scope and p.permissions == ("design.write",)
    )
    assert p.effect is Effect.DENY and p.enforce is True and p.hide is False
    assert p.condition == {"exists": {"attr": "action.permission"}}
    assert p.description == "undecodable stored policy: denies (fail closed)"
    default = Policy.fail_closed("x", scope)
    assert default.permissions == ("*",)
    assert Policy.fail_closed("Bad Id", scope).id == "invalid-policy"


def test_hashes_are_value_based():
    a, b = Policy.from_new(np()), Policy.from_new(np())
    assert hash(a) == hash(b) and len({a, b}) == 1
    assert hash(Policy.from_new(np(), revision=1)) != hash(a)
    assert hash(Policy.from_new(np(), status=PolicyStatus.DISABLED)) != hash(a)
    assert hash(np()) == hash(np()) and hash(np(id="p2")) != hash(np())
    ref = EntityRef.principal("u1")
    assert hash(EntityAttributes(ref, {"a": 1}, 0)) == hash(
        EntityAttributes(ref, {"b": 2}, 0)
    )
    assert hash(EntityAttributes(ref, {}, 1)) != hash(EntityAttributes(ref, {}, 0))
    assert hash(EntityAttributes(EntityRef.principal("u2"), {}, 0)) != hash(
        EntityAttributes(ref, {}, 0)
    )


# --------------------------------------------------------------- validation


def problems(catalog, policy, **kw):
    with pytest.raises(InvalidPolicyError) as exc:
        validate_policy(policy, catalog, **kw)
    return list(exc.value.problems)


def test_problems_carry_the_location_of_the_offending_node(catalog):
    ghost = {"attr": "subject.attrs.ghost"}
    cond = {"all": [{"eq": [{"attr": "subject.id"}, "x"]}, {"not": {"eq": [ghost, 1]}}]}
    assert problems(catalog, np(condition=cond)) == [
        "/all/1/not/0/eq/0: undeclared attribute subject.attrs.ghost"
    ]
    assert problems(catalog, np(condition={"exists": ghost})) == [
        "/exists: undeclared attribute subject.attrs.ghost"
    ]
    one_missing = {"eq": [ghost, {"attr": "subject.id"}]}
    assert problems(catalog, np(condition=one_missing)) == [
        "/eq/0: undeclared attribute subject.attrs.ghost"
    ]  # no spurious type error for the operand that is fine
    both = {"eq": [ghost, {"attr": "subject.attrs.ghost2"}]}
    assert len(problems(catalog, np(condition=both))) == 2


def test_type_rules_with_exact_messages(catalog):
    clearance = {"attr": "subject.attrs.clearance"}
    assert problems(catalog, np(condition={"eq": [clearance, "3"]})) == [
        "/eq: eq compares number with string"
    ]
    assert problems(catalog, np(condition={"eq": [clearance, None]})) == [
        "/eq: eq compares number with null"
    ]
    assert problems(catalog, np(condition={"eq": [clearance, True]})) == [
        "/eq: eq compares number with bool"
    ]
    assert problems(
        catalog, np(condition={"eq": [{"attr": "subject.groups"}, ["a"]]})
    ) == ["/eq: eq compares set with set"]
    assert problems(catalog, np(condition={"lt": [{"attr": "subject.id"}, "x"]})) == [
        "/lt: lt needs numbers or datetimes, got string"
    ]
    assert problems(catalog, np(condition={"starts_with": [clearance, "x"]})) == [
        "/starts_with: starts_with needs two strings"
    ]
    assert problems(catalog, np(condition={"subset": [clearance, [1]]})) == [
        "/subset: subset needs two sets"
    ]
    assert problems(catalog, np(condition={"in": [clearance, 3]})) == [
        "/in: in needs (value, set)"
    ]
    assert problems(catalog, np(condition={"not_in": [None, ["a"]]})) == [
        "/not_in: not_in needs (value, set)"
    ]
    assert problems(
        catalog, np(condition={"in": [{"attr": "subject.groups"}, ["a"]]})
    ) == ["/in: in needs (value, set)"]
    assert problems(catalog, np(condition={"in": [clearance, [1, "x"]]})) == [
        "/in: set items must be of type number"
    ]
    assert problems(catalog, np(condition={"not_in": [clearance, [1, "x"]]})) == [
        "/not_in: set items must be of type number"
    ]
    assert problems(
        catalog, np(condition={"in": [clearance, {"attr": "subject.groups"}]})
    ) == ["/in: a string_set attribute holds strings"]
    assert problems(catalog, np(condition={"contains": [clearance, 1]})) == [
        "/contains: contains needs (set, value) or (string, string)"
    ]
    assert problems(
        catalog, np(condition={"contains": [{"attr": "subject.groups"}, ["a"]]})
    ) == ["/contains: contains needs (set, value) or (string, string)"]


def test_valid_forms_of_contains_in_and_comparisons(catalog):
    validate_policy(np(condition={"contains": [{"attr": "subject.id"}, "x"]}), catalog)
    validate_policy(
        np(condition={"contains": [{"attr": "subject.groups"}, "g"]}), catalog
    )
    validate_policy(np(condition={"in": [{"attr": "subject.id"}, ["a", "b"]]}), catalog)
    validate_policy(
        np(condition={"in": [{"attr": "subject.id"}, {"attr": "subject.groups"}]}),
        catalog,
    )
    validate_policy(np(condition={"eq": [{"attr": "env.hour_utc"}, 5]}), catalog)
    validate_policy(np(condition={"eq": [{"attr": "env.hour_utc"}, 5.5]}), catalog)


def test_datetime_literals_in_either_operand_order(catalog):
    now, iso = {"attr": "env.now"}, "2030-01-01T00:00:00+00:00"
    validate_policy(np(condition={"lt": [now, iso]}), catalog)
    validate_policy(np(condition={"lt": [iso, now]}), catalog)  # literal on the left
    assert problems(catalog, np(condition={"lt": ["garbage", now]})) == [
        "/lt: lt compares string with datetime"
    ]
    assert problems(catalog, np(condition={"lt": ["2030-01-01T00:00:00", now]})) == [
        "/lt: lt compares string with datetime"
    ]
    assert problems(catalog, np(condition={"lt": [{"attr": "subject.id"}, now]})) == [
        "/lt: lt compares string with datetime"
    ]  # an attribute is never coerced
    assert problems(catalog, np(condition={"lt": [now, 5]})) == [
        "/lt: lt compares datetime with number"
    ]
    assert problems(catalog, np(condition={"lt": [now, {"attr": "subject.id"}]})) == [
        "/lt: lt compares datetime with string"
    ]


def test_literal_type_names_in_messages(catalog):
    assert problems(catalog, np(condition={"eq": [None, True]})) == [
        "/eq: eq compares null with bool"
    ]
    assert problems(catalog, np(condition={"eq": [True, "x"]})) == [
        "/eq: eq compares bool with string"
    ]


def test_enum_checks_cover_every_literal(catalog):
    status = {"attr": "subject.assignment.tenant_status"}
    assert problems(catalog, np(condition={"eq": [status, "frozen"]})) == [
        "/eq: ['frozen'] not in the enum of subject.assignment.tenant_status"
    ]
    assert problems(catalog, np(condition={"ne": ["frozen", status]})) == [
        "/ne: ['frozen'] not in the enum of subject.assignment.tenant_status"
    ]
    assert problems(catalog, np(condition={"in": [status, ["active", "x", "y"]]})) == [
        "/in: ['x', 'y'] not in the enum of subject.assignment.tenant_status"
    ]
    validate_policy(np(condition={"in": [status, ["active", "suspended"]]}), catalog)


def test_scope_permission_and_flag_problems_are_exact(catalog):
    assert problems(catalog, np(scope=PolicyScope("ghost"))) == [
        "unknown scope kind: ghost",
        "pattern 'design.write' spans scope kinds other than ghost: ['design.write']",
    ]
    assert problems(catalog, np(permissions=("nope.*",))) == [
        "permission pattern 'nope.*' matches nothing"
    ]
    assert problems(catalog, np(effect=Effect.PERMIT)) == [
        "permit policies need mode='grant'"
    ]
    assert problems(
        catalog, np(effect=Effect.PERMIT, hide=True), allow_permit=True
    ) == ["hide only applies to deny/require policies"]
    validate_policy(np(effect=Effect.REQUIRE, hide=True), catalog)
