from __future__ import annotations

import json
from enum import StrEnum

import pytest

from auth_middleware.authz import (
    CatalogError,
    PermissionCatalog,
    PermissionSpec,
    ScopeKind,
    UnknownPermissionError,
)


def test_reports_all_problems_at_once():
    with pytest.raises(CatalogError) as exc:
        PermissionCatalog.from_mapping(
            scopes=[ScopeKind("studio")],
            permissions=[
                PermissionSpec("a.b", "studio"),
                PermissionSpec("a.b", "studio"),
                PermissionSpec("c.d", "nowhere"),
                PermissionSpec("Bad Name", "studio"),
                PermissionSpec("", "studio"),
            ],
            roles={"R": ["ghost"], "": ["a.b"]},
        )
    msg = str(exc.value)
    for fragment in (
        "duplicate permission: a.b",
        "undeclared scope kind nowhere",
        "invalid permission name: 'Bad Name'",
        "empty permission name",
        "undeclared permission ghost",
        "empty role name",
    ):
        assert fragment in msg


def test_lookups(catalog):
    assert catalog.permissions_for("READER") == {"design.read"}
    assert catalog.permissions_for("NOBODY") == frozenset()
    assert catalog.roles_granting("design.read") == {"OWNER", "EDITOR", "READER"}
    assert catalog.spec("members.manage").sensitive
    assert catalog.scope_kind("global").hide_existence is False
    with pytest.raises(CatalogError):
        catalog.permissions_for("unknown")
    with pytest.raises(UnknownPermissionError):
        catalog.spec("nope")
    with pytest.raises(CatalogError):
        catalog.scope_kind("nope")


def test_round_trip(catalog):
    again = PermissionCatalog.from_mapping(**catalog.to_mapping())
    assert again.to_mapping() == catalog.to_mapping()


def test_returned_sets_are_immutable_views(catalog):
    got = catalog.permissions_for("OWNER")
    assert isinstance(got, frozenset)
    assert catalog.roles() == {"OWNER", "EDITOR", "READER", "NOBODY", "PLATFORM_ADMIN"}


def test_accepts_str_enums():
    class P(StrEnum):
        X = "x.y"

    cat = PermissionCatalog.from_mapping(
        scopes=[ScopeKind("studio")],
        permissions=[PermissionSpec(P.X, "studio")],
        roles={"R": [P.X]},
    )
    assert cat.spec(P.X).name == "x.y"
    assert cat.permissions_for("R") == {"x.y"}


def test_from_file_toml_and_json(tmp_path):
    toml = tmp_path / "c.toml"
    toml.write_text(
        '[[scopes]]\nname = "studio"\n\n[[permissions]]\nname = "a.b"\n'
        'scope = "studio"\nsensitive = true\n\n[roles]\nR = ["a.b"]\n'
    )
    cat = PermissionCatalog.from_file(toml)
    assert cat.spec("a.b").sensitive
    js = tmp_path / "c.json"
    js.write_text(
        json.dumps(
            {
                "scopes": [{"name": "studio"}],
                "permissions": [{"name": "a.b", "scope": "studio"}],
                "roles": {"R": ["a.b"]},
            }
        )
    )
    assert PermissionCatalog.from_file(js).permissions_for("R") == {"a.b"}
    with pytest.raises(CatalogError):
        PermissionCatalog.from_file(tmp_path / "missing.toml")
    bad = tmp_path / "c.txt"
    bad.write_text("")
    with pytest.raises(CatalogError):
        PermissionCatalog.from_file(bad)
