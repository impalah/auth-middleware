"""OpenAPI helpers: publish and audit the permission of each operation."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRoute

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def permission_extra(permission: str) -> dict[str, str]:
    """Return ``{"x-permission": permission}`` for ``openapi_extra=``."""
    return {"x-permission": str(permission)}


def declared_permissions(app: FastAPI) -> dict[tuple[str, str], str | None]:
    """Map ``(METHOD, path)`` to the ``x-permission`` of every operation.

    Operations without ``x-permission`` map to ``None``. Meant for architecture
    tests ("every route declares a permission").
    """
    result: dict[tuple[str, str], str | None] = {}
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.include_in_schema:
            continue
        extra = route.openapi_extra or {}
        value = extra.get("x-permission")
        for method in (route.methods or set()) & _HTTP_METHODS:
            result[(method, route.path)] = str(value) if value is not None else None
    return result
