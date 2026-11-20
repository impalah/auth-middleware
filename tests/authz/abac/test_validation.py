"""AUTHZ-025: attribute schema and policy validation."""

from __future__ import annotations

import json

import pytest

from auth_middleware.authz import PermissionCatalog
from auth_middleware.authz.abac.schema import AttributeSchema, AttributeSpec
from auth_middleware.authz.abac.types import Effect, NewPolicy, PolicyScope
from auth_middleware.authz.abac.validation import (
    policy_matches_permission,
    validate_policy,
)
from auth_middleware.authz.errors import CatalogError, InvalidPolicyError

STATUS = {"attr": "subject.assignment.tenant_status"}


def pol(cond, **kw):
    base = dict(
        id="p",
        effect=Effect.DENY,
        permissions=("design.write",),
        scope=PolicyScope("studio"),
        condition=cond,
    )
    base.update(kw)
    return NewPolicy(**base)


def problems(policy, catalog, **kw):
    with pytest.raises(InvalidPolicyError) as exc:
        validate_policy(policy, catalog, **kw)
    return " | ".join(exc.value.problems)


def test_valid_policy_passes(catalog):
    validate_policy(
        pol({"eq": [STATUS, "suspended"]}, permissions=("*.write",)), catalog
    )
    validate_policy(
        pol(
            {
                "all": [
                    {"gte": [{"attr": "subject.attrs.clearance"}, 3]},
                    {"lt": [{"attr": "env.now"}, "2030-01-01T00:00:00+00:00"]},
                    {"in": [{"attr": "env.method"}, ["GET", "HEAD"]]},
                    {"intersects": [{"attr": "subject.groups"}, ["a"]]},
                    {"contains": [{"attr": "subject.attrs.tags"}, "x"]},
                    {"starts_with": [{"attr": "env.path"}, "/api"]},
                    {"exists": {"attr": "resource.attrs.owner_id"}},
                    {
                        "eq": [
                            {"attr": "resource.attrs.owner_id"},
                            {"attr": "subject.id"},
                        ]
                    },
                    {"gt": [{"attr": "resource.attrs.created"}, {"attr": "env.now"}]},
                ]
            },
            effect=Effect.REQUIRE,
            hide=True,
        ),
        catalog,
    )


def test_old_catalog_files_still_load_and_have_builtins(tmp_path):
    f = tmp_path / "c.json"
    f.write_text(
        json.dumps(
            {
                "scopes": [{"name": "s"}],
                "permissions": [{"name": "a.b", "scope": "s"}],
                "roles": {"R": ["a.b"]},
            }
        )
    )
    cat = PermissionCatalog.from_file(f)
    assert "subject.id" in cat.attributes and cat.attributes.declared == {}
    assert "attributes" not in cat.to_mapping()


def test_catalog_attributes_round_trip(catalog, tmp_path):
    again = PermissionCatalog.from_mapping(**catalog.to_mapping())
    assert dict(again.attributes.declared) == dict(catalog.attributes.declared)
    f = tmp_path / "c.toml"
    f.write_text(
        '[[scopes]]\nname="s"\n[[permissions]]\nname="a.b"\nscope="s"\n[roles]\nR=["a.b"]\n'
        '[attributes."subject.attrs.level"]\ntype="int"\nenum=[1,2]\n'
    )
    cat = PermissionCatalog.from_file(f)
    spec = cat.attributes.spec("subject.attrs.level")
    assert spec and spec.type == "int" and spec.enum == (1, 2)


@pytest.mark.parametrize(
    "spec",
    [
        AttributeSpec("subject.id", "string"),
        AttributeSpec("subject.attrs.x", "weird"),
        AttributeSpec("bogus.x", "string"),
        AttributeSpec("subject.attrs.x", "bool", (True,)),
        AttributeSpec("subject.other.x", "string"),
        AttributeSpec("subject.attrs.x", "string", ()),
    ],
)
def test_invalid_attribute_declarations(spec):
    with pytest.raises(CatalogError):
        PermissionCatalog.from_mapping(
            scopes=[], permissions=[], roles={}, attributes=[spec]
        )


def test_duplicate_attribute_declaration():
    s = AttributeSpec("subject.attrs.x", "int")
    with pytest.raises(CatalogError):
        PermissionCatalog.from_mapping(
            scopes=[], permissions=[], roles={}, attributes=[s, s]
        )


def test_schema_is_immutable_view():
    schema = AttributeSchema(
        {"subject.attrs.x": AttributeSpec("subject.attrs.x", "int")}
    )
    assert "subject.attrs.x" in schema and "nope" not in schema and 5 not in schema
    with pytest.raises(TypeError):
        schema.declared["a"] = 1  # type: ignore[index]
    assert schema.spec("subject.attrs.x.y") is None  # leaves only


def test_unknown_permission_and_kind_and_span(catalog):
    assert "matches nothing" in problems(
        pol({"eq": [1, 1]}, permissions=("nope.*",)), catalog
    )
    assert "spans scope kinds" in problems(
        pol({"eq": [1, 1]}, permissions=("*",)), catalog
    )
    assert "unknown scope kind" in problems(
        pol({"eq": [1, 1]}, scope=PolicyScope("ghost")), catalog
    )
    assert "global policy" in problems(
        pol(
            {"eq": [1, 1]}, permissions=("admin.all",), scope=PolicyScope("global", "x")
        ),
        catalog,
    )


def test_attribute_and_type_rules(catalog):
    A = {"attr": "subject.attrs.clearance"}
    assert "undeclared attribute subject.attrs.nope" in problems(
        pol({"eq": [{"attr": "subject.attrs.nope"}, 1]}), catalog
    )
    assert "compares number with string" in problems(pol({"eq": [A, "3"]}), catalog)
    assert "needs numbers or datetimes" in problems(
        pol({"lt": [{"attr": "subject.id"}, {"attr": "env.method"}]}), catalog
    )
    assert "needs two strings" in problems(pol({"starts_with": [A, "x"]}), catalog)
    assert "needs (value, set)" in problems(pol({"in": [A, 3]}), catalog)
    assert "set items must be of type number" in problems(
        pol({"in": [A, [1, "x"]]}), catalog
    )
    assert "holds strings" in problems(
        pol({"in": [A, {"attr": "subject.groups"}]}), catalog
    )
    assert "contains needs" in problems(pol({"contains": [A, 1]}), catalog)
    assert "needs two sets" in problems(pol({"subset": [A, [1]]}), catalog)
    assert "not in the enum" in problems(pol({"eq": [STATUS, "frozen"]}), catalog)
    assert "not in the enum" in problems(
        pol({"in": [STATUS, ["active", "x"]]}), catalog
    )
    assert "compares datetime with string" in problems(
        pol({"lt": [{"attr": "env.now"}, "garbage"]}), catalog
    )
    assert "compares datetime with string" in problems(
        pol({"lt": [{"attr": "env.now"}, "2030-01-01T00:00:00"]}), catalog
    )


def test_effect_and_hide_rules(catalog):
    c = {"eq": [1, 1]}
    assert "mode='grant'" in problems(pol(c, effect=Effect.PERMIT), catalog)
    validate_policy(pol(c, effect=Effect.PERMIT), catalog, allow_permit=True)
    assert "hide only applies" in problems(
        pol(c, effect=Effect.PERMIT, hide=True), catalog, allow_permit=True
    )


def test_all_problems_are_listed_at_once(catalog):
    p = pol(
        {"eq": [{"attr": "subject.attrs.nope"}, 1]},
        permissions=("zzz.*",),
        effect=Effect.PERMIT,
    )
    with pytest.raises(InvalidPolicyError) as exc:
        validate_policy(p, catalog)
    assert len(exc.value.problems) >= 3


def test_condition_syntax_error_is_reported(catalog):
    assert "unknown operator" in problems(pol({"bogus": [1, 2]}), catalog)


def test_pattern_matching():
    assert policy_matches_permission("*.write", "design.write")
    assert policy_matches_permission("design.*", "design.read")
    assert not policy_matches_permission("design.write", "design.writer")
    assert policy_matches_permission("*", "anything.at.all")
