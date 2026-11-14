from __future__ import annotations

import pytest
from examples import authz_stores_config as cfg
from starlette.requests import Request


def test_every_configuration_builds_without_connecting():
    assert cfg.memory_authz()
    assert cfg.sql_authz("sqlite+aiosqlite:///:memory:")
    assert cfg.dynamodb_authz(
        "authz", region="us-east-1", endpoint_url="http://localhost:1"
    )
    assert cfg.sql_per_request_authz()


@pytest.mark.asyncio
async def test_per_request_factory_uses_the_request_session():
    authz = cfg.sql_per_request_authz()
    sentinel = object()
    request = Request({"type": "http", "headers": [], "app": None})
    request.state.session = sentinel
    authorizer = await authz.authorizer_for(request)
    assert authorizer is not None
