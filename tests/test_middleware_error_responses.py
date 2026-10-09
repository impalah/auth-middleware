"""Auth middleware error responses: correct status, and no internal details."""

import base64
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey
from starlette.datastructures import Headers, State

from auth_middleware import BasicAuthMiddleware, JwtAuthMiddleware
from auth_middleware.contracts import CredentialsRepository
from auth_middleware.guards import require_user
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.oidc.oidc_provider_settings import (
    OidcProviderSettings,
)
from auth_middleware.types.user_credentials import UserCredentials

LEAKY_MESSAGE = "password=hunter2 at db.internal:5432"


def _jwt_app() -> FastAPI:
    app = FastAPI()
    provider = OidcProvider(
        settings=OidcProviderSettings(
            issuer="https://idp.invalid/",
            audience="client",
            jwks_uri="https://idp.invalid/jwks",
        )
    )
    app.add_middleware(JwtAuthMiddleware, auth_provider=provider)

    @app.get("/protected", dependencies=[Depends(require_user())])
    async def protected() -> dict[str, bool]:
        return {"ok": True}

    return app


class TestJwtMiddlewareErrors:
    def test_non_bearer_scheme_is_a_client_error_not_a_500(self) -> None:
        client = TestClient(_jwt_app(), raise_server_exceptions=False)

        response = client.get(
            "/protected", headers={"Authorization": "Basic YWJjOmRlZg=="}
        )

        assert response.status_code in (401, 403)
        assert "Server error" not in response.text

    @pytest.mark.parametrize("token", ["garbage", "aaa.bbb.ccc"])
    def test_malformed_bearer_token_is_401(self, token: str) -> None:
        client = TestClient(_jwt_app(), raise_server_exceptions=False)

        response = client.get(
            "/protected", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid token"}

    def test_missing_credentials_are_rejected_by_the_guard(self) -> None:
        client = TestClient(_jwt_app(), raise_server_exceptions=False)

        assert client.get("/protected").status_code == 401

    @pytest.mark.asyncio
    async def test_http_exception_keeps_its_status_and_headers(
        self, mock_auth_provider
    ) -> None:
        middleware = JwtAuthMiddleware(Mock(), auth_provider=mock_auth_provider)
        request = Mock(spec=Request)
        request.state = State()
        middleware.get_current_user = AsyncMock(
            side_effect=HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
                headers={"WWW-Authenticate": "Bearer"},
            )
        )

        response = await middleware.dispatch(request, AsyncMock())

        assert isinstance(response, JSONResponse)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.headers["www-authenticate"] == "Bearer"

    @pytest.mark.asyncio
    async def test_unexpected_error_does_not_leak_its_message(
        self, mock_auth_provider
    ) -> None:
        middleware = JwtAuthMiddleware(Mock(), auth_provider=mock_auth_provider)
        request = Mock(spec=Request)
        request.state = State()
        middleware.get_current_user = AsyncMock(side_effect=Exception(LEAKY_MESSAGE))

        response = await middleware.dispatch(request, AsyncMock())

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.body == b'{"detail":"Internal server error"}'
        assert b"hunter2" not in response.body


class _FixedKeysProvider(OidcProvider):
    def __init__(self, keys: list[dict], **kwargs) -> None:
        super().__init__(**kwargs)
        self._keys = keys

    async def get_keys(self) -> list[dict]:
        return self._keys


class TestJwtWithoutKid:
    """A token with no "kid" header (or a JWKS key without one) is a bad token: 401."""

    @staticmethod
    def _client(jwks_keys: list[dict]) -> TestClient:
        app = FastAPI()
        provider = _FixedKeysProvider(
            jwks_keys,
            settings=OidcProviderSettings(
                issuer="https://idp.invalid/",
                audience="client",
                jwks_uri="https://idp.invalid/jwks",
            ),
        )
        app.add_middleware(JwtAuthMiddleware, auth_provider=provider)

        @app.get("/protected", dependencies=[Depends(require_user())])
        async def protected() -> dict[str, bool]:
            return {"ok": True}

        return TestClient(app, raise_server_exceptions=False)

    @staticmethod
    def _token(key: RSAKey, header: dict) -> str:
        claims = {
            "iss": "https://idp.invalid/",
            "aud": "client",
            "sub": "u",
            "exp": 4_000_000_000,
        }
        return jwt.encode(header, claims, key)

    def test_token_without_kid_is_401_not_500(self) -> None:
        key = RSAKey.generate_key(2048, auto_kid=True)
        client = self._client([key.as_dict(private=False)])

        response = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {self._token(key, {'alg': 'RS256'})}"},
        )

        assert response.status_code == 401

    def test_jwks_entry_without_kid_is_skipped_not_fatal(self) -> None:
        key = RSAKey.generate_key(2048, auto_kid=True)
        keyless = {k: v for k, v in key.as_dict(private=False).items() if k != "kid"}
        client = self._client([keyless])

        response = client.get(
            "/protected",
            headers={
                "Authorization": "Bearer "
                + self._token(key, {"alg": "RS256", "kid": key.kid})
            },
        )

        assert response.status_code == 401

    def test_a_correct_token_is_still_accepted(self) -> None:
        key = RSAKey.generate_key(2048, auto_kid=True)
        client = self._client([key.as_dict(private=False)])

        response = client.get(
            "/protected",
            headers={
                "Authorization": "Bearer "
                + self._token(key, {"alg": "RS256", "kid": key.kid})
            },
        )

        assert response.status_code == 200


class _ExplodingRepository(CredentialsRepository):
    async def get_by_id(self, *, id: str) -> UserCredentials | None:
        raise RuntimeError(LEAKY_MESSAGE)


class TestBasicMiddlewareErrors:
    @pytest.mark.asyncio
    async def test_unexpected_error_does_not_leak_its_message(self) -> None:
        middleware = BasicAuthMiddleware(
            app=Mock(), credentials_repository=_ExplodingRepository()
        )
        request = Mock(spec=Request)
        request.state = State()
        token = base64.b64encode(b"user:pass").decode()
        request.headers = Headers({"authorization": f"Basic {token}"})

        response = await middleware.dispatch(request, AsyncMock())

        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.body == b'{"detail":"Internal server error"}'
        assert b"hunter2" not in response.body


class TestBasicMiddlewareRegistration:
    def test_add_middleware_as_documented_in_the_readme(self) -> None:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.add_middleware(
            BasicAuthMiddleware, credentials_repository=_ExplodingRepository()
        )

        @app.get("/")
        async def root() -> dict[str, str]:
            return {"ok": "yes"}

        # Building the stack is what used to raise TypeError.
        assert TestClient(app, raise_server_exceptions=False).get("/").status_code in (
            200,
            401,
        )


class TestEmailClaim:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("ada@home.local", "ada@home.local"),
            ("ada@corp.internal", "ada@corp.internal"),
            ("ada@box.localhost", "ada@box.localhost"),
            ("Ada@Example.com", "Ada@example.com"),
            ("", None),
            ("   ", None),
            (None, None),
        ],
    )
    def test_reserved_domains_and_blanks_are_accepted(
        self, raw: str | None, expected: str | None
    ) -> None:
        from auth_middleware.types.user import User

        assert User(id="u", email=raw).email == expected

    @pytest.mark.parametrize(
        "raw", ["not-an-email", "a b@home.local", "@home.local", "ada@-bad.local"]
    )
    def test_malformed_addresses_are_still_rejected(self, raw: str) -> None:
        from pydantic import ValidationError

        from auth_middleware.types.user import User

        with pytest.raises(ValidationError):
            User(id="u", email=raw)
