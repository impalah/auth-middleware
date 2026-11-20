"""The ABAC example and its policy file (also shown in the documentation)."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from auth_middleware.authz.abac import AbacConfig, StaticPolicySource
from auth_middleware.authz.abac.validation import validate_policy


@pytest.fixture(scope="module")
def mod():
    return importlib.import_module("examples.abac_example")


def at(hour):
    return lambda: datetime(2026, 11, 20, hour, 0, tzinfo=UTC)


def test_every_documented_policy_parses_and_validates(mod):
    source = StaticPolicySource.from_file(mod.POLICIES)
    assert len(source.policies) == 5
    for policy in source.policies:
        validate_policy(policy, mod.catalog)
    mod.Authz.build(
        catalog=mod.catalog,
        store=mod.InMemoryAssignmentStore(),
        abac=AbacConfig(policies=source),
    )


def call(client, method, url, user):
    return getattr(client, method)(url, headers={"x-user": user}).status_code


def test_the_scenarios_of_the_docstring(mod):
    with TestClient(mod.build_app(clock=at(12))) as c:
        assert call(c, "get", "/studios/s1/designs/d1", "alice") == 200
        assert call(c, "delete", "/studios/s1/designs/d1", "alice") == 200
        assert call(c, "delete", "/studios/s1/designs/d2", "alice") == 404  # not hers
        assert call(c, "delete", "/studios/s1/designs/zzz", "alice") == 404
        assert call(c, "put", "/studios/s2/designs/d1", "carol") == 403  # suspended
        assert (
            call(c, "get", "/studios/s2/designs/d1", "carol") == 200
        )  # reads still work
        assert call(c, "get", "/studios/s1/docs/secret", "alice") == 200  # clearance 3
        assert call(c, "get", "/studios/s1/docs/public", "bob") == 200
        assert call(c, "get", "/studios/s1/docs/secret", "bob") == 403  # clearance 1
        assert call(c, "get", "/studios/s1/billing", "bob") == 403  # support: never
        assert call(c, "get", "/studios/s1/billing", "alice") == 200


def test_support_office_hours(mod):
    with TestClient(mod.build_app(clock=at(3))) as night:
        assert call(night, "get", "/studios/s1/designs/d1", "bob") == 403
        assert call(night, "get", "/studios/s1/designs/d1", "alice") == 200
    with TestClient(mod.build_app(clock=at(9))) as day:
        assert call(day, "get", "/studios/s1/designs/d1", "bob") == 200
    with TestClient(mod.build_app(clock=at(20))) as closing:
        assert call(closing, "get", "/studios/s1/designs/d1", "bob") == 403


def test_openapi_publishes_x_abac(mod):
    schema = mod.build_app().openapi()
    delete = schema["paths"]["/studios/{studio_id}/designs/{design_id}"]["delete"]
    assert delete["x-abac"] is True and delete["x-permission"] == "design.delete"
    read = schema["paths"]["/studios/{studio_id}/designs/{design_id}"]["get"]
    assert "x-abac" not in read
