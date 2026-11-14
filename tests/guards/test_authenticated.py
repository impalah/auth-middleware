from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from auth_middleware.guards import (
    get_current_user,
    get_identity,
    require_authenticated,
    require_user,
)
from auth_middleware.settings import settings
from auth_middleware.types.identity import Identity
from auth_middleware.types.user import User


class Inject(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        kind = request.headers.get("x-kind")
        if kind == "synthetic":
            request.state.current_user = User.synthetic()
        elif kind == "full":
            request.state.current_user = User(
                id="u1", name="Una", email="una@example.com", groups=["a", "b"]
            )
        elif kind == "bare":
            request.state.current_user = User(id="u2", groups=[])
        return await call_next(request)


def _client(**kw) -> TestClient:
    app = FastAPI()
    app.add_middleware(Inject)

    @app.get("/user")
    async def user(u=Depends(require_authenticated(**kw))):
        return {"id": u.id}

    @app.get("/identity")
    async def identity(i: Identity = Depends(get_identity(**kw))):
        return {
            "sub": i.sub,
            "email": i.email,
            "name": i.name,
            "groups": list(i.groups),
        }

    return TestClient(app)


@pytest.mark.parametrize("path", ["/user", "/identity"])
def test_no_user_and_synthetic_are_401(path):
    client = _client()
    for headers in ({}, {"x-kind": "synthetic"}):
        r = client.get(path, headers=headers)
        assert r.status_code == 401
        assert r.json() == {"detail": "Authentication required"}
        assert r.headers["www-authenticate"] == "Bearer"


def test_synthetic_allowed_on_request():
    assert (
        _client(allow_synthetic=True)
        .get("/user", headers={"x-kind": "synthetic"})
        .status_code
        == 200
    )


def test_real_user_and_identity_resolution():
    client = _client()
    assert client.get("/user", headers={"x-kind": "full"}).json() == {"id": "u1"}
    assert client.get("/identity", headers={"x-kind": "full"}).json() == {
        "sub": "u1",
        "email": "una@example.com",
        "name": "Una",
        "groups": ["a", "b"],
    }


def test_identity_fallbacks_for_missing_email_and_name():
    body = _client().get("/identity", headers={"x-kind": "bare"}).json()
    assert body == {"sub": "u2", "email": "", "name": "u2", "groups": []}


def test_custom_unauthenticated_responder():
    class Problem(Exception):
        pass

    client = TestClient(
        _client(on_unauthenticated=lambda request: Problem("uniform")).app,
        raise_server_exceptions=True,
    )
    with pytest.raises(Problem):
        client.get("/user")


def test_stays_closed_when_authentication_is_disabled(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MIDDLEWARE_DISABLED", True)
    client = _client()
    assert client.get("/user", headers={"x-kind": "synthetic"}).status_code == 401
    # while the legacy guard keeps its documented "never blocked" behaviour
    app = FastAPI()
    app.add_middleware(Inject)

    @app.get("/legacy", dependencies=[Depends(require_user())])
    async def legacy():
        return {}

    assert TestClient(app).get("/legacy").status_code == 200


def test_legacy_names_still_exported():
    assert callable(require_user) and callable(get_current_user)
    assert HTTPException
