"""Regression tests for the second round of the 0.7.0 quality remediation."""

from __future__ import annotations

import asyncio
import inspect
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from loguru import logger as loguru_logger

from auth_middleware.exceptions.identity_provider_unavailable_exception import (
    IdentityProviderUnavailableException,
)
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
from auth_middleware.password_hasher import (
    DEFAULT_ITERATIONS,
    hash_password,
    needs_rehash,
)
from auth_middleware.providers.aws.services.async_cognito_auth_service import (
    AsyncCognitoAuthService,
)
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.oidc.oidc_provider_settings import OidcProviderSettings
from auth_middleware.types.jwt import JWTAuthorizationCredentials


def _oidc(**kw) -> OidcProvider:
    kw.setdefault("jwks_background_refresh", False)
    return OidcProvider(
        settings=OidcProviderSettings(
            issuer="https://idp.example/",
            audience="mine",
            jwks_uri="https://idp/jwks",
            **kw,
        )
    )


def _bearer(sub="u") -> str:
    import base64
    import json

    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{enc({'alg': 'RS256', 'kid': 'k'})}.{enc({'sub': sub})}.sig"


# ------------------------------------------------- identity provider outage = 503


@pytest.mark.asyncio
async def test_unreachable_jwks_endpoint_is_an_outage_not_a_bad_token():
    provider = _oidc()
    with patch(
        "auth_middleware.providers.oidc.oidc_provider.httpx.AsyncClient.get",
        side_effect=httpx.ConnectError("down"),
    ):
        with pytest.raises(IdentityProviderUnavailableException) as exc:
            await provider.get_keys()
    assert exc.value.status_code == 503
    assert isinstance(exc.value, InvalidTokenException)  # old except clauses still work


def test_middleware_answers_503_when_the_identity_provider_is_down():
    provider = MagicMock()
    provider.verify_token = AsyncMock(
        side_effect=IdentityProviderUnavailableException(
            status_code=503, detail="Unable to reach identity provider"
        )
    )
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, auth_provider=provider)

    @app.get("/")
    async def root(request: Request):
        return {}

    r = TestClient(app).get("/", headers={"Authorization": f"Bearer {_bearer()}"})
    assert r.status_code == 503
    assert r.headers["retry-after"] == "5"
    assert "reach" not in r.text  # nothing about the upstream leaks


def test_a_signed_token_that_cannot_become_a_user_is_401_not_500():
    provider = _oidc()
    provider.verify_token = AsyncMock(return_value=True)  # signature ok...
    app = FastAPI()
    app.add_middleware(JwtAuthMiddleware, auth_provider=provider)

    @app.get("/")
    async def root():
        return {}

    # ...but the token has no `sub` and no client id: OidcException -> 401
    r = TestClient(app, raise_server_exceptions=False).get(
        "/", headers={"Authorization": f"Bearer {_bearer(sub='')}"}
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_background_refresh_task_is_cancelled_on_aclose():
    provider = _oidc()
    gate = asyncio.get_running_loop().create_future()
    provider._background_refresh_task = asyncio.ensure_future(gate)
    await provider.aclose()
    assert gate.cancelled() and provider._background_refresh_task is None


# ----------------------------------------------------------------- entra


@pytest.mark.asyncio
async def test_entra_user_gets_the_token_and_the_providers():
    from auth_middleware.providers.azure.entra_id_provider import EntraIDProvider

    perms, roles = MagicMock(), MagicMock()
    provider = EntraIDProvider(permissions_provider=perms, roles_provider=roles)
    creds = JWTAuthorizationCredentials(
        jwt_token="a.b.c",
        header={"alg": "RS256"},
        claims={"sub": "u", "preferred_username": "una"},
        signature="c",
        message="a.b",
    )
    user = await provider.create_user_from_token(creds)
    assert user._token == "a.b.c" and user._permissions_provider is perms
    assert user._roles_provider is roles


def test_entra_jwks_cache_is_configurable():
    from auth_middleware.providers.azure.settings import settings

    assert settings.AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES == 20
    assert settings.AUTH_MIDDLEWARE_JWKS_CACHE_USAGES == 1000


# ------------------------------------------------------------ passwords / sql


def test_needs_rehash_flags_legacy_weak_and_malformed_hashes():
    import hashlib

    assert needs_rehash(hashlib.sha256(b"x").hexdigest())  # legacy unsalted
    assert needs_rehash(hash_password("x", iterations=1000))  # too few iterations
    assert needs_rehash("pbkdf2_sha256$abc$aa$bb")
    assert not needs_rehash(hash_password("x"))
    assert not needs_rehash(hash_password("x", iterations=1000), iterations=1000)
    assert DEFAULT_ITERATIONS >= 600_000


@pytest.mark.parametrize("claim", ["preferred_username", "email"])
@pytest.mark.parametrize("module", ["sql_groups_provider", "sql_permissions_provider"])
def test_editable_id_claims_warn(claim, module):
    import importlib

    mod = importlib.import_module(f"auth_middleware.providers.sqlalchemy.{module}")
    cls = next(
        v
        for k, v in vars(mod).items()
        if k.startswith("Sql") and k.endswith("Provider")
    )
    messages: list[str] = []
    sink = loguru_logger.add(lambda m: messages.append(str(m)), level="WARNING")
    try:
        cls(id_claim="sub")
        assert not messages
        cls(id_claim=claim)
    finally:
        loguru_logger.remove(sink)
    assert any("impersonate" in m for m in messages)


def test_sql_statement_echo_is_its_own_setting():
    from auth_middleware.providers.sqlalchemy.async_database_settings import settings

    assert settings.AUTHZ_ECHO is False


# --------------------------------------------------------- cognito async facade


@pytest.mark.asyncio
async def test_async_cognito_facade_runs_calls_in_a_worker_thread():
    seen: dict[str, int] = {}
    service = MagicMock()

    def login(username, password):
        seen["thread"] = threading.get_ident()
        return "tokens"

    service.login = login
    service.logout.return_value = "bye"
    facade = AsyncCognitoAuthService(service)
    assert await facade.login("u", "p") == "tokens"
    assert seen["thread"] != threading.get_ident()  # the event loop thread is free
    assert await facade.logout("tok") == "bye"
    for name in (
        "respond_to_challenge",
        "refresh",
        "get_user",
        "change_password",
        "forgot_password",
        "reset_password",
        "setup_totp",
        "verify_totp",
        "disable_totp",
    ):
        assert inspect.iscoroutinefunction(getattr(facade, name))
