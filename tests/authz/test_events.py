from __future__ import annotations

import asyncio
import json
import logging

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from auth_middleware.authz import (
    Authz,
    AuthzHooks,
    NewAssignment,
    ScopeFromPath,
    ScopeRef,
    require_permission,
)
from auth_middleware.authz.events import audit_hook, combine_hooks, metrics_hook
from auth_middleware.authz.stores import InMemoryAssignmentStore
from auth_middleware.services.audit import AuditLogger
from auth_middleware.services.metrics import MetricsCollector
from auth_middleware.types.user import User


class Auth(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        who = request.headers.get("x-user")
        if who:
            request.state.current_user = User(
                id=who, name="Secret Name", email=f"{who}@secret.example", groups=[]
            )
        return await call_next(request)


def _client(catalog, hooks):
    store = InMemoryAssignmentStore()

    async def fill():
        s = ScopeRef("studio", "s1")
        await store.assign(NewAssignment("owner", s, "OWNER"))
        await store.assign(NewAssignment("reader", s, "READER"))

    asyncio.run(fill())
    app = FastAPI()
    app.add_middleware(Auth)
    Authz.build(catalog=catalog, store=store, hooks=hooks).install(app)

    @app.get("/s/{sid}/read")
    async def read(
        sid: str,
        ctx=Depends(
            require_permission("design.read", scope=ScopeFromPath("studio", "sid"))
        ),
    ):
        return {}

    @app.get("/s/{sid}/members")
    async def members(
        sid: str,
        ctx=Depends(
            require_permission("members.manage", scope=ScopeFromPath("studio", "sid"))
        ),
    ):
        return {}

    return TestClient(app)


def test_hook_called_once_per_decision_with_right_kind(catalog):
    events = []
    client = _client(catalog, AuthzHooks(on_decision=events.append))
    client.get("/s/s1/read", headers={"x-user": "reader", "x-request-id": "req-1"})
    client.get("/s/s1/members", headers={"x-user": "reader"})
    client.get("/s/s1/read", headers={"x-user": "stranger"})
    client.get("/s/s1/members", headers={"x-user": "owner"})
    assert [e.kind.value for e in events] == [
        "allowed",
        "denied",
        "not_visible",
        "allowed",
    ]
    assert events[0].request_id == "req-1" and events[0].roles == {"READER"}
    assert events[0].duration_ms >= 0 and events[0].sensitive is False
    assert events[2].roles == frozenset()
    assert events[3].sensitive is True


def test_failing_hook_does_not_change_the_response(catalog):
    def boom(event):
        raise RuntimeError("audit sink down")

    client = _client(catalog, AuthzHooks(on_decision=boom))
    assert client.get("/s/s1/read", headers={"x-user": "reader"}).status_code == 200
    assert client.get("/s/s1/members", headers={"x-user": "reader"}).status_code == 403


def test_metrics_counters(catalog):
    collector = MetricsCollector()
    client = _client(catalog, AuthzHooks(on_decision=metrics_hook(collector)))
    client.get("/s/s1/read", headers={"x-user": "reader"})
    client.get("/s/s1/read", headers={"x-user": "reader"})
    client.get("/s/s1/members", headers={"x-user": "reader"})
    client.get("/s/s1/read", headers={"x-user": "stranger"})
    snapshot = asyncio.run(collector.get_authz_metrics())
    assert snapshot["decisions"] == {"allowed": 2, "denied": 1, "not_visible": 1}
    assert snapshot["by_permission"]["design.read"] == {"allowed": 2, "not_visible": 1}


def test_audit_levels_and_privacy(catalog, caplog):
    seen = []
    audit = AuditLogger(log_callback=seen.append)
    client = _client(catalog, AuthzHooks(on_decision=combine_hooks(audit_hook(audit))))
    with caplog.at_level(logging.DEBUG):
        client.get("/s/s1/read", headers={"x-user": "reader"})  # allowed, DEBUG
        client.get(
            "/s/s1/members", headers={"x-user": "owner"}
        )  # allowed sensitive, INFO
        client.get("/s/s1/members", headers={"x-user": "reader"})  # denied, WARNING
        client.get("/s/s1/read", headers={"x-user": "stranger"})  # not visible, INFO
    levels = [r.levelno for r in caplog.records if r.getMessage() == "AUDIT: authz"]
    assert levels == [logging.DEBUG, logging.INFO, logging.WARNING, logging.INFO]
    assert all(e.event_type == "authz" for e in seen)
    blob = json.dumps([e.to_dict() for e in seen]) + " ".join(
        r.getMessage() for r in caplog.records
    )
    assert "secret.example" not in blob and "Secret Name" not in blob


def test_event_serialisation_has_ids_only():
    from auth_middleware.authz import DecisionEvent
    from auth_middleware.authz.types import DecisionKind

    data = DecisionEvent(
        DecisionKind.DENIED, "u1", ScopeRef("studio", "s1"), "a.b"
    ).to_dict()
    json.dumps(data)
    assert set(data) == {
        "kind",
        "principal_id",
        "scope_kind",
        "scope_id",
        "permission",
        "roles",
        "sensitive",
        "duration_ms",
        "request_id",
    }
