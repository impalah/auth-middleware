"""Options of JwtAuthMiddleware: canonical Bearer, path prefix, error responder."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
from starlette.routing import Mount

from auth_middleware.jwt_auth_middleware import AuthFailure, JwtAuthMiddleware
from auth_middleware.types.jwt import JWTAuthorizationCredentials
from auth_middleware.types.user import User


class FakeProvider:
    """Validates ``sub`` starting with ``good`` and the configured audience."""

    def __init__(self, audience: str = "") -> None:
        self.audience = audience

    async def verify_token(self, token: JWTAuthorizationCredentials) -> bool:
        sub = str(token.claims.get("sub", ""))
        return sub.startswith("good") and token.claims.get("aud") == self.audience

    async def create_user_from_token(self, token: JWTAuthorizationCredentials) -> User:
        sub = token.claims["sub"]
        return User(id=sub, name=sub, groups=[])


def _jwt(sub: str, aud: str = "a") -> str:
    import base64
    import json

    def enc(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{enc({'alg': 'x'})}.{enc({'sub': sub, 'aud': aud})}.sig"


RealisticProvider = FakeProvider


def _app(**options) -> TestClient:
    app = FastAPI()
    app.add_middleware(
        JwtAuthMiddleware, auth_provider=RealisticProvider("a"), **options
    )

    @app.get("/who")
    async def who(request: Request):
        user = getattr(request.state, "current_user", "unset")
        return {"user": user.id if isinstance(user, User) else str(user)}

    return TestClient(app)


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "bEaReR"])
def test_canonical_bearer_scheme_accepts_any_spelling(scheme):
    client = _app(canonical_bearer_scheme=True)
    r = client.get("/who", headers={"Authorization": f"{scheme} {_jwt('good1')}"})
    assert r.status_code == 200 and r.json() == {"user": "good1"}


def test_default_still_rejects_lowercase_scheme():
    client = _app()
    r = client.get("/who", headers={"Authorization": f"bearer {_jwt('good1')}"})
    assert r.status_code == 401


def test_other_schemes_keep_their_status_and_other_headers_untouched():
    client = _app(canonical_bearer_scheme=True)
    r = client.get("/who", headers={"Authorization": "Basic Zm9vOmJhcg=="})
    assert r.status_code in (401, 403)
    assert (
        r.status_code
        == _app()
        .get("/who", headers={"Authorization": "Basic Zm9vOmJhcg=="})
        .status_code
    )
    seen = {}
    app = FastAPI()
    app.add_middleware(
        JwtAuthMiddleware,
        auth_provider=RealisticProvider("a"),
        canonical_bearer_scheme=True,
    )

    @app.get("/h")
    async def h(request: Request):
        seen.update(request.headers)
        return {}

    TestClient(app).get(
        "/h", headers={"Authorization": f"bearer {_jwt('good1')}", "X-Other": "keep"}
    )
    assert seen["x-other"] == "keep"
    assert seen["authorization"].startswith("Bearer ")


def test_path_prefix_skips_other_paths_without_setting_a_user():
    app = FastAPI()
    app.add_middleware(
        JwtAuthMiddleware,
        auth_provider=RealisticProvider("a"),
        path_prefix="/api/studio/v1",
    )

    @app.get("/api/studio/v1/who")
    @app.get("/api/studio/v1")
    @app.get("/api/studio/v10/who")
    @app.get("/public/who")
    async def who(request: Request):
        return {"has_user": hasattr(request.state, "current_user")}

    client = TestClient(app)
    assert client.get("/public/who").json() == {"has_user": False}
    # prefix match is on whole segments: /v10 is outside /v1
    assert client.get("/api/studio/v10/who").json() == {"has_user": False}
    # inside: validated (bad token -> 401), valid token -> user set
    assert (
        client.get(
            "/api/studio/v1/who", headers={"Authorization": "Bearer junk"}
        ).status_code
        == 401
    )
    ok = client.get(
        "/api/studio/v1/who",
        headers={"Authorization": f"Bearer {_jwt('good1')}"},
    )
    assert ok.json() == {"has_user": True}
    assert (
        client.get(
            "/api/studio/v1", headers={"Authorization": f"Bearer {_jwt('good1')}"}
        ).status_code
        == 200
    )


def test_two_middlewares_on_two_prefixes_with_different_audiences():
    """ARTISEVM's studio/platform case: each subtree validates its own audience."""
    root = FastAPI()
    studio = FastAPI()
    platform = FastAPI()

    @studio.get("/who")
    async def s(request: Request):
        return {"user": request.state.current_user.id}

    @platform.get("/who")
    async def p(request: Request):
        return {"user": request.state.current_user.id}

    root.add_middleware(
        JwtAuthMiddleware,
        auth_provider=RealisticProvider("studio-aud"),
        path_prefix="/studio",
    )
    root.add_middleware(
        JwtAuthMiddleware,
        auth_provider=RealisticProvider("platform-aud"),
        path_prefix="/platform",
    )
    root.router.routes.append(Mount("/studio", app=studio))
    root.router.routes.append(Mount("/platform", app=platform))
    client = TestClient(root)
    studio_token = {"Authorization": f"Bearer {_jwt('good-s', 'studio-aud')}"}
    platform_token = {"Authorization": f"Bearer {_jwt('good-p', 'platform-aud')}"}
    assert client.get("/studio/who", headers=studio_token).status_code == 200
    assert client.get("/platform/who", headers=platform_token).status_code == 200
    assert client.get("/studio/who", headers=platform_token).status_code == 401
    assert client.get("/platform/who", headers=studio_token).status_code == 401


def test_error_responder_for_invalid_token_bad_scheme_and_internal(monkeypatch):
    seen: list[AuthFailure] = []

    def responder(request, failure: AuthFailure):
        seen.append(failure)
        return JSONResponse({"type": "problem"}, status_code=failure.status_code)

    client = _app(error_responder=responder, canonical_bearer_scheme=True)
    assert client.get("/who", headers={"Authorization": "Bearer junk"}).json() == {
        "type": "problem"
    }
    client.get("/who", headers={"Authorization": "Basic Zm9vOmJhcg=="})
    monkeypatch.setattr(
        JwtAuthMiddleware,
        "get_current_user",
        AsyncMock(side_effect=RuntimeError("secret connection string")),
    )
    r = client.get("/who", headers={"Authorization": f"Bearer {_jwt('good1')}"})
    assert r.status_code == 500 and "secret" not in r.text
    assert [f.reason for f in seen] == ["invalid_token", "bad_scheme", "internal"]
    assert all("secret" not in repr(f) for f in seen)


def test_default_bodies_unchanged():
    client = _app()
    r = client.get("/who", headers={"Authorization": "Bearer junk"})
    assert r.status_code == 401
    assert r.json() == {"detail": "Invalid token"}
    assert r.headers["www-authenticate"] == "Bearer"
