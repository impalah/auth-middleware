"""Attribute-based access control on top of scoped permissions.

Run:  uv run uvicorn examples.abac_example:app
A tiny middleware stands in for ``JwtAuthMiddleware``: it trusts the ``x-user`` header.
NEVER do that outside an example; use a real JWT provider.

Roles say what a member can do in a studio; the policies in ``abac_policies.toml``
refine that with the data of the request (tenant status, owner of a design, hour of
the day, clearance versus document classification). Try::

    curl -H 'x-user: alice' localhost:8000/studios/s1/designs/d1          # 200
    curl -X DELETE -H 'x-user: alice' localhost:8000/studios/s1/designs/d2 # 404 (not hers)
    curl -X PUT    -H 'x-user: carol' localhost:8000/studios/s2/designs/d1 # 403 (suspended)
    curl -H 'x-user: alice' localhost:8000/studios/s1/docs/secret          # 200 (clearance 3)
    curl -H 'x-user: bob'   localhost:8000/studios/s1/billing              # 403 (support)
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

from auth_middleware.authz import (
    Authz,
    AuthzContext,
    NewAssignment,
    PermissionCatalog,
    PermissionSpec,
    ScopeFromPath,
    ScopeKind,
    ScopeRef,
    permission_extra,
    require_permission,
)
from auth_middleware.authz.abac import (
    AbacConfig,
    AttributeSpec,
    EntityRef,
    ResourceFromPath,
    StaticPolicySource,
)
from auth_middleware.authz.stores import InMemoryAssignmentStore, InMemoryAttributeStore
from auth_middleware.types.user import User

POLICIES = Path(__file__).with_name("abac_policies.toml")

catalog = PermissionCatalog.from_mapping(
    scopes=[ScopeKind("studio")],
    permissions=[
        PermissionSpec("design.read", "studio"),
        PermissionSpec("design.write", "studio"),
        PermissionSpec("design.delete", "studio", sensitive=True),
        PermissionSpec("doc.read", "studio"),
        PermissionSpec("billing.read", "studio"),
    ],
    roles={
        "OWNER": [
            "design.read",
            "design.write",
            "design.delete",
            "doc.read",
            "billing.read",
        ],
        "EDITOR": ["design.read", "design.write", "doc.read"],
        "SUPPORT": ["design.read", "doc.read", "billing.read"],
    },
    # The attributes policies may read besides the built-in ones (subject.id,
    # subject.roles, env.hour_utc...). A policy naming anything else is rejected.
    attributes=[
        AttributeSpec(
            "subject.assignment.tenant_status", "string", ("active", "suspended")
        ),
        AttributeSpec("subject.attrs.clearance", "int"),
        AttributeSpec("resource.attrs.owner_id", "string"),
        AttributeSpec("resource.attrs.classification", "int"),
    ],
)

# The application's own data. In real code this is your database.
DESIGNS = {"d1": {"owner_id": "alice"}, "d2": {"owner_id": "dave"}}
DOCS = {"public": {"classification": 0}, "secret": {"classification": 3}}


def design_attributes(request, ref):
    """Resource loader: the attributes of a design (``None``: it does not exist)."""
    return DESIGNS.get(ref.id)


def doc_attributes(request, ref):
    return DOCS.get(ref.id)


class DemoAuth(BaseHTTPMiddleware):
    """Example only: trusts a header instead of validating a token."""

    async def dispatch(self, request, call_next):
        who = request.headers.get("x-user")
        if who:
            request.state.current_user = User(id=who, name=who, groups=[])
        return await call_next(request)


def build_app(clock: Callable[[], datetime] | None = None) -> FastAPI:
    """Build the demo app (``clock`` is injectable so tests can pick the hour)."""
    assignments = InMemoryAssignmentStore()
    attributes = InMemoryAttributeStore()

    async def seed() -> None:
        s1, s2 = ScopeRef("studio", "s1"), ScopeRef("studio", "s2")
        active = {"tenant_status": "active"}
        await assignments.assign(NewAssignment("alice", s1, "OWNER", active))
        await assignments.assign(NewAssignment("bob", s1, "SUPPORT", active))
        await assignments.assign(
            NewAssignment("carol", s2, "EDITOR", {"tenant_status": "suspended"})
        )
        for who, level in (("alice", 3), ("bob", 1)):
            await attributes.put_attributes(
                EntityRef.principal(who), {"clearance": level}, expected_revision=None
            )

    asyncio.run(seed())

    config = AbacConfig(
        policies=StaticPolicySource.from_file(POLICIES),
        attributes=attributes,
        **({"clock": clock} if clock else {}),
    )
    authz = Authz.build(catalog=catalog, store=assignments, abac=config)

    app = FastAPI()
    app.add_middleware(DemoAuth)
    studio = ScopeFromPath("studio", "studio_id")

    @app.get(
        "/studios/{studio_id}/designs/{design_id}",
        openapi_extra=permission_extra("design.read"),
    )
    async def read_design(
        design_id: str,
        ctx: AuthzContext = Depends(require_permission("design.read", scope=studio)),
    ):
        return {"design": design_id, "viewer": ctx.principal.id}

    @app.put(
        "/studios/{studio_id}/designs/{design_id}",
        openapi_extra=permission_extra("design.write"),
    )
    async def write_design(
        design_id: str,
        ctx: AuthzContext = Depends(require_permission("design.write", scope=studio)),
    ):
        return {"design": design_id, "saved": True}

    @app.delete(
        "/studios/{studio_id}/designs/{design_id}",
        openapi_extra=permission_extra("design.delete", abac=True),
    )
    async def delete_design(
        design_id: str,
        ctx: AuthzContext = Depends(
            require_permission(
                "design.delete",
                scope=studio,
                resource=ResourceFromPath("design", "design_id", design_attributes),
            )
        ),
    ):
        return {"design": design_id, "deleted": True}

    @app.get(
        "/studios/{studio_id}/docs/{doc_id}",
        openapi_extra=permission_extra("doc.read", abac=True),
    )
    async def read_doc(
        doc_id: str,
        ctx: AuthzContext = Depends(
            require_permission(
                "doc.read",
                scope=studio,
                resource=ResourceFromPath("doc", "doc_id", doc_attributes),
            )
        ),
    ):
        return {"doc": doc_id}

    @app.get(
        "/studios/{studio_id}/billing", openapi_extra=permission_extra("billing.read")
    )
    async def billing(
        ctx: AuthzContext = Depends(require_permission("billing.read", scope=studio)),
    ):
        return {"invoices": []}

    authz.install(app)
    return app


app = build_app()
