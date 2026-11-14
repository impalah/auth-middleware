from __future__ import annotations

import httpx
import pytest
from examples.authz_example import app, seed


async def _call(method: str, path: str, **headers: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        return await client.request(method, path, headers=headers)


@pytest.mark.asyncio
async def test_example_behaviour():
    await seed()
    ok = await _call("GET", "/studios/s1/design", **{"x-user": "raul"})
    assert ok.status_code == 200 and ok.json() == {"studio": "s1", "roles": ["READER"]}
    assert (
        await _call("PUT", "/studios/s1/design", **{"x-user": "ana"})
    ).status_code == 200
    denied = await _call("PUT", "/studios/s1/design", **{"x-user": "raul"})
    assert denied.status_code == 403
    assert denied.json()["detail"]["required_permission"] == "design.write"
    assert (
        await _call("GET", "/studios/s1/design", **{"x-user": "eve"})
    ).status_code == 404
    assert (
        await _call("GET", "/studios/zz/design", **{"x-user": "ana"})
    ).status_code == 404
    assert (await _call("GET", "/studios/s1/design")).status_code == 401
    assert (
        await _call(
            "GET",
            "/platform/status",
            **{"x-user": "pat", "x-groups": "platform-admins"},
        )
    ).status_code == 200
    assert (
        await _call("GET", "/platform/status", **{"x-user": "ana"})
    ).status_code == 403
