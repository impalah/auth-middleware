"""Scoped permissions: a tenant-scoped route and a platform route.

Run:  uv run uvicorn examples.authz_example:app
A tiny middleware stands in for ``JwtAuthMiddleware``: it trusts the ``x-user`` and
``x-groups`` headers. NEVER do that outside an example; use a real JWT provider.
"""

from __future__ import annotations

import asyncio

from fastapi import Depends, FastAPI, Request
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
from auth_middleware.authz.stores import InMemoryAssignmentStore
from auth_middleware.types.user import User

catalog = PermissionCatalog.from_mapping(
    scopes=[ScopeKind("studio"), ScopeKind("global", hide_existence=False)],
    permissions=[
        PermissionSpec("design.read", "studio"),
        PermissionSpec("design.write", "studio"),
        PermissionSpec("platform.admin", "global", sensitive=True),
    ],
    roles={
        "EDITOR": ["design.read", "design.write"],
        "READER": ["design.read"],
        "PLATFORM_ADMIN": ["platform.admin"],
    },
)

store = InMemoryAssignmentStore()
studio = ScopeFromPath("studio", "studio_id")  # the scope is a path parameter


class DemoAuth(BaseHTTPMiddleware):
    """Example only: trusts headers instead of validating a token."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        who = request.headers.get("x-user")
        if who:
            groups = [g for g in request.headers.get("x-groups", "").split(",") if g]
            request.state.current_user = User(id=who, name=who, groups=groups)
        return await call_next(request)


async def seed() -> None:
    await store.assign(NewAssignment("ana", ScopeRef("studio", "s1"), "EDITOR"))
    await store.assign(NewAssignment("raul", ScopeRef("studio", "s1"), "READER"))


app = FastAPI(on_startup=[seed])
app.add_middleware(DemoAuth)
Authz.build(
    catalog=catalog,
    store=store,
    group_roles={"platform-admins": "PLATFORM_ADMIN"},  # token group -> global role
).install(app)


@app.get(
    "/studios/{studio_id}/design",
    openapi_extra=permission_extra("design.read"),
)
async def read_design(
    studio_id: str,
    ctx: AuthzContext = Depends(require_permission("design.read", scope=studio)),
) -> dict[str, object]:
    return {"studio": studio_id, "roles": sorted(ctx.roles)}


@app.put("/studios/{studio_id}/design", openapi_extra=permission_extra("design.write"))
async def write_design(
    studio_id: str,
    ctx: AuthzContext = Depends(require_permission("design.write", scope=studio)),
) -> dict[str, bool]:
    return {"saved": True}


@app.get("/platform/status", openapi_extra=permission_extra("platform.admin"))
async def platform_status(
    ctx: AuthzContext = Depends(require_permission("platform.admin")),
) -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(seed())
