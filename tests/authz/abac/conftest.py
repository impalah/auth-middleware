from __future__ import annotations

import pytest

from auth_middleware.authz import PermissionCatalog, PermissionSpec, ScopeKind
from auth_middleware.authz.abac.schema import AttributeSpec


@pytest.fixture
def catalog() -> PermissionCatalog:
    return PermissionCatalog.from_mapping(
        scopes=[ScopeKind("studio"), ScopeKind("global", hide_existence=False)],
        permissions=[
            PermissionSpec("design.read", "studio"),
            PermissionSpec("design.write", "studio"),
            PermissionSpec("design.delete", "studio", sensitive=True),
            PermissionSpec("billing.read", "studio"),
            PermissionSpec("admin.all", "global"),
        ],
        roles={
            "EDI": ["design.read", "design.write"],
            "OWN": ["design.read", "design.write", "design.delete", "billing.read"],
            "ADM": ["admin.all"],
        },
        attributes=[
            AttributeSpec(
                "subject.assignment.tenant_status", "string", ("active", "suspended")
            ),
            AttributeSpec("subject.attrs.clearance", "int"),
            AttributeSpec("subject.attrs.tags", "string_set"),
            AttributeSpec("resource.attrs.owner_id", "string"),
            AttributeSpec("resource.attrs.classification", "int"),
            AttributeSpec("resource.attrs.created", "datetime"),
            AttributeSpec("subject.claims.dept", "string"),
            AttributeSpec("env.header.x_tenant", "string"),
        ],
    )
