from __future__ import annotations

import pytest

from auth_middleware.authz import PermissionCatalog, PermissionSpec, ScopeKind


@pytest.fixture
def catalog() -> PermissionCatalog:
    return PermissionCatalog.from_mapping(
        scopes=[ScopeKind("studio"), ScopeKind("global", hide_existence=False)],
        permissions=[
            PermissionSpec("design.read", "studio"),
            PermissionSpec("design.write", "studio"),
            PermissionSpec("members.manage", "studio", sensitive=True),
            PermissionSpec("platform.admin", "global"),
        ],
        roles={
            "OWNER": ["design.read", "design.write", "members.manage"],
            "EDITOR": ["design.read", "design.write"],
            "READER": ["design.read"],
            "NOBODY": [],
            "PLATFORM_ADMIN": ["platform.admin"],
        },
    )
