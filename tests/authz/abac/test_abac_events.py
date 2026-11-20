"""AUTHZ-034: ABAC in audit events, metrics, explain output and shadow mode."""

from __future__ import annotations

import logging

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from auth_middleware.authz import (
    Authz,
    AuthzHooks,
    DecisionKind,
    NewAssignment,
    ScopeFromPath,
    ScopeRef,
    require_permission,
)
from auth_middleware.authz.abac.config import AbacConfig
from auth_middleware.authz.abac.sources import StaticPolicySource
from auth_middleware.authz.abac.types import Effect, NewPolicy, PolicyScope
from auth_middleware.authz.events import audit_hook, combine_hooks, metrics_hook
from auth_middleware.authz.runtime import DecisionEvent
from auth_middleware.authz.stores import InMemoryAssignmentStore
from auth_middleware.services.audit import AuditLogger
from auth_middleware.services.metrics import MAX_POLICY_SERIES, MetricsCollector

from .test_guard_abac import STATUS, FakeAuth

SECRET = "ultra-secret-tenant-state"
DENY = NewPolicy(
    "deny-susp",
    Effect.DENY,
    ("design.write",),
    PolicyScope("studio"),
    {"eq": [STATUS, "suspended"]},
)
SHADOW = NewPolicy(
    "shadow-susp",
    Effect.DENY,
    ("design.write",),
    PolicyScope("studio"),
    {"eq": [STATUS, "suspended"]},
    enforce=False,
)


def make(catalog, *policies, status="suspended", hooks=None):
    store = InMemoryAssignmentStore()

    async def fill():
        await store.assign(
            NewAssignment(
                "u1",
                ScopeRef("studio", "s1"),
                "EDI",
                {"tenant_status": status, "note": SECRET},
            )
        )

    import asyncio

    asyncio.run(fill())
    authz = Authz.build(
        catalog=catalog,
        store=store,
        hooks=hooks,
        abac=AbacConfig(policies=StaticPolicySource(policies), policy_cache_ttl=0),
    )
    app = FastAPI()
    app.add_middleware(FakeAuth)

    @app.put(
        "/studios/{studio_id}/x",
        dependencies=[
            Depends(
                require_permission(
                    "design.write", scope=ScopeFromPath("studio", "studio_id")
                )
            )
        ],
    )
    async def put(studio_id: str):
        return {}

    authz.install(app)
    return TestClient(app)


def test_denial_event_has_ids_and_reason_but_no_values(catalog):
    events: list[DecisionEvent] = []
    with make(catalog, DENY, hooks=AuthzHooks(on_decision=events.append)) as c:
        assert c.put("/studios/s1/x", headers={"x-user": "u1"}).status_code == 403
    (event,) = events
    assert event.kind is DecisionKind.DENIED
    assert event.policy_ids == ("deny-susp",) and event.abac_reason == "deny:deny-susp"
    dumped = repr(event.to_dict())
    assert SECRET not in dumped and "suspended" not in dumped


def test_shadow_policy_reports_without_changing_the_status(catalog):
    events: list[DecisionEvent] = []
    with make(catalog, SHADOW, hooks=AuthzHooks(on_decision=events.append)) as c:
        assert c.put("/studios/s1/x", headers={"x-user": "u1"}).status_code == 200
    (event,) = events
    assert event.kind is DecisionKind.ALLOWED and event.policy_ids == ()
    assert event.shadow_policy_ids == ("shadow-susp",)


def test_events_are_unchanged_without_abac():
    event = DecisionEvent(DecisionKind.ALLOWED, "u1", ScopeRef("studio", "s1"), "p.x")
    assert set(event.to_dict()) == {
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
    full = DecisionEvent(
        DecisionKind.DENIED,
        "u1",
        ScopeRef("studio", "s1"),
        "p.x",
        policy_ids=("a",),
        shadow_policy_ids=("b",),
        abac_reason="deny:a",
    )
    assert (
        full.to_dict()["policy_ids"] == ["a"]
        and full.to_dict()["abac_reason"] == "deny:a"
    )


def test_audit_levels_for_abac(catalog, caplog):
    seen: list = []
    audit = AuditLogger(log_to_console=True, log_callback=seen.append)
    records: list[tuple[int, str]] = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append((record.levelno, record.getMessage()))

    audit.logger.addHandler(Capture())
    audit.logger.setLevel(logging.DEBUG)
    with make(catalog, SHADOW, hooks=AuthzHooks(on_decision=audit_hook(audit))) as c:
        c.put("/studios/s1/x", headers={"x-user": "u1"})
    assert records and records[-1][0] == logging.INFO  # allowed, but shadow would deny
    assert seen and seen[0].to_dict()["shadow_policy_ids"] == ["shadow-susp"]


@pytest.mark.asyncio
async def test_metrics_count_policies_and_stay_0_7_0_without_abac():
    collector = MetricsCollector()
    hook = metrics_hook(collector)
    plain = DecisionEvent(DecisionKind.ALLOWED, "u1", ScopeRef("studio", "s1"), "p.x")
    await hook(plain)
    assert await collector.get_authz_metrics() == {
        "decisions": {"allowed": 1},
        "by_permission": {"p.x": {"allowed": 1}},
    }
    denied = DecisionEvent(
        DecisionKind.DENIED,
        "u1",
        ScopeRef("studio", "s1"),
        "p.x",
        policy_ids=("a",),
        shadow_policy_ids=("s",),
    )
    await hook(denied)
    data = await collector.get_authz_metrics()
    assert data["by_source"] == {"abac": 1}
    assert data["abac_policies"] == {"a": {"denied": 1}, "s": {"shadow_denied": 1}}


@pytest.mark.asyncio
async def test_policy_metric_cardinality_is_capped():
    collector = MetricsCollector()
    for i in range(MAX_POLICY_SERIES + 400):
        await collector.record_abac_policy(f"p{i}", "denied")
    data = (await collector.get_authz_metrics())["abac_policies"]
    assert len(data) == MAX_POLICY_SERIES + 1  # tracked ids + "other"
    assert data["other"]["denied"] == 400


@pytest.mark.asyncio
async def test_combined_hooks_still_work():
    collector = MetricsCollector()
    seen: list = []
    hook = combine_hooks(seen.append, metrics_hook(collector))
    await hook(
        DecisionEvent(DecisionKind.ALLOWED, "u1", ScopeRef("studio", "s1"), "p.x")
    )
    assert len(seen) == 1
