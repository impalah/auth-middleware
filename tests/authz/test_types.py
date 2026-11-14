from __future__ import annotations

import dataclasses

import pytest

import auth_middleware.authz as authz
from auth_middleware.authz import (
    Assignment,
    AssignmentStatus,
    AssignmentStore,
    PermissionDeniedError,
    Principal,
    ScopeNotVisibleError,
    ScopeRef,
)
from auth_middleware.authz.errors import AuthzError, RevisionConflictError


@pytest.mark.parametrize(
    "kind,id_",
    [
        ("Bad Kind", "x"),
        ("studio", ""),
        ("studio", "*"),
        ("studio", "x" * 201),
        ("", "x"),
    ],
)
def test_scope_ref_rejects_invalid(kind, id_):
    with pytest.raises(ValueError):
        ScopeRef(kind, id_)


def test_global_scope_and_equality():
    assert ScopeRef.GLOBAL == ScopeRef("global", "*")
    assert len({ScopeRef("studio", "a"), ScopeRef("studio", "a")}) == 1
    assert ScopeRef("studio", "x" * 200)


def test_immutable_and_hashable():
    a = Assignment("u", ScopeRef("studio", "a"), "R", AssignmentStatus.ACTIVE)
    hash(a)
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.role = "X"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        Principal("u").id = "v"  # type: ignore[misc]


def test_error_hierarchy():
    scope = ScopeRef("studio", "a")
    denied = PermissionDeniedError("design.write", scope)
    assert denied.required == "design.write" and denied.scope == scope
    assert isinstance(ScopeNotVisibleError(scope), AuthzError)
    assert isinstance(RevisionConflictError(), AuthzError)


def test_protocol_conformance_with_trivial_fake():
    class Fake:
        async def get_assignment(self, principal_id, scope):
            return None

        async def list_assignments(self, principal_id):
            return []

    assert isinstance(Fake(), AssignmentStore)
    assert not isinstance(object(), AssignmentStore)


def test_import_pulls_no_optional_dependency():
    import subprocess
    import sys

    code = (
        "import sys, auth_middleware.authz;"
        "bad=[m for m in sys.modules if m.split('.')[0] in ('sqlalchemy','aioboto3','pynamodb','boto3')];"
        "sys.exit(1 if bad else 0)"
    )
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0


def test_public_names_exported():
    for name in authz.__all__:
        assert hasattr(authz, name)
