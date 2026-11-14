"""Regression tests for the issues found by the 0.7.0 quality review (legacy code)."""

from __future__ import annotations

import asyncio
import base64
import logging
from time import time_ns
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from loguru import logger as loguru_logger

from auth_middleware.basic_auth_middleware import BasicAuthMiddleware
from auth_middleware.guards.group_checker import GroupChecker
from auth_middleware.guards.role_checker import RoleChecker
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
from auth_middleware.password_hasher import hash_password, verify_password
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.oidc.oidc_provider_settings import OidcProviderSettings
from auth_middleware.providers.sqlalchemy.async_database import _safe_url
from auth_middleware.services.audit import AuditMiddleware
from auth_middleware.services.metrics import MetricsCollector
from auth_middleware.services.rate_limiter import RateLimiter, _resolve_identifier
from auth_middleware.settings import settings
from auth_middleware.types.jwt import JWTAuthorizationCredentials
from auth_middleware.types.user import User
from auth_middleware.types.user_credentials import UserCredentials

# ---------------------------------------------------------------- basic auth


class Repo:
    def __init__(self, users: dict[str, UserCredentials]) -> None:
        self.users = users

    async def get_by_id(self, *, id: str):
        return self.users.get(id)


def _basic_client(users) -> TestClient:
    app = FastAPI()
    app.add_middleware(BasicAuthMiddleware, credentials_repository=Repo(users))

    @app.get("/")
    async def root(request: Request):
        return {"user": getattr(request.state.current_user, "id", None)}

    return TestClient(app)


def _basic(user: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def alice() -> UserCredentials:
    return UserCredentials(
        id="alice",
        name="Alice",
        hashed_password=hash_password("s3cret", iterations=1000),
    )


def test_basic_auth_never_logs_the_password(alice):
    messages: list[str] = []
    sink = loguru_logger.add(lambda m: messages.append(str(m)), level="DEBUG")
    try:
        client = _basic_client({"alice": alice})
        client.get("/", headers=_basic("alice", "TOPSECRET-password"))
        client.get("/", headers=_basic("alice", "s3cret"))
    finally:
        loguru_logger.remove(sink)
    assert not any("TOPSECRET" in m or "s3cret" in m for m in messages)


def test_unknown_user_and_wrong_password_are_indistinguishable(alice):
    client = _basic_client({"alice": alice})
    with patch(
        "auth_middleware.basic_auth_middleware.verify_password", return_value=False
    ) as verify:
        unknown = client.get("/", headers=_basic("nobody", "x"))
        wrong = client.get("/", headers=_basic("alice", "x"))
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()
    assert verify.call_count == 2  # the hash is verified even for an unknown user
    assert client.get("/", headers=_basic("alice", "s3cret")).json() == {
        "user": "alice"
    }


@pytest.mark.parametrize(
    "header",
    ["Basic !!!not-base64!!!", "Basic " + base64.b64encode(b"no-colon").decode()],
)
def test_malformed_basic_header_is_401_not_500(alice, header):
    r = _basic_client({"alice": alice}).get("/", headers={"Authorization": header})
    assert r.status_code == 401


# -------------------------------------------------------------------- guards


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "checker_cls,prop", [(GroupChecker, "groups"), (RoleChecker, "roles")]
)
async def test_none_from_a_provider_fails_closed(checker_cls, prop):
    user = MagicMock()
    setattr(type(user), prop, property(lambda self: asyncio.sleep(0, result=None)))
    request = MagicMock()
    request.state.current_user = user
    with patch.object(settings, "AUTH_MIDDLEWARE_DISABLED", False):
        with pytest.raises(HTTPException) as exc:
            await checker_cls(["admin"])(request)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------- user


@pytest.mark.asyncio
async def test_lazy_providers_receive_the_parsed_credentials():
    creds = JWTAuthorizationCredentials(
        jwt_token="a.b.c",
        header={"alg": "x"},
        claims={"sub": "u"},
        signature="c",
        message="a.b",
    )
    provider = MagicMock()
    provider.fetch_permissions = AsyncMock(return_value=["p"])
    user = User(
        id="u", token="a.b.c", jwt_credentials=creds, permissions_provider=provider
    )
    assert await user.permissions == ["p"]
    provider.fetch_permissions.assert_awaited_once_with(creds)


@pytest.mark.asyncio
async def test_oidc_user_token_is_the_jwt_not_its_repr():
    provider = OidcProvider(
        settings=OidcProviderSettings(issuer="https://i/", require_audience=False)
    )
    creds = JWTAuthorizationCredentials(
        jwt_token="aaa.bbb.ccc",
        header={"alg": "RS256"},
        claims={"sub": "u", "preferred_username": "una"},
        signature="ccc",
        message="aaa.bbb",
    )
    user = await provider.create_user_from_token(creds)
    assert user._token == "aaa.bbb.ccc"


@pytest.mark.asyncio
async def test_cancelling_one_waiter_does_not_poison_the_shared_load():
    gate = asyncio.Event()
    provider = MagicMock()

    async def slow(_token):
        await gate.wait()
        return ["g"]

    provider.fetch_groups = slow
    user = User(id="u", token="t", groups_provider=provider)
    first = asyncio.create_task(user.groups)
    await asyncio.sleep(0)
    first.cancel()
    gate.set()
    assert await user.groups == ["g"]


# ----------------------------------------------------------- password hasher


@pytest.mark.parametrize(
    "stored",
    [
        "pbkdf2_sha256$0$aa$bb",
        "pbkdf2_sha256$-5$aa$bb",
        "pbkdf2_sha256$999999999999$aa$bb",
        "pbkdf2_sha256$1000$zz$bb",
        "pbkdf2_sha256$1000$aa$not-hex",
        "ñandú-non-ascii-legacy",
    ],
)
def test_corrupt_stored_hashes_are_a_clean_false(stored):
    assert verify_password("x", stored) is False


# ------------------------------------------------------ rate limit, audit, metrics


def test_rate_limiter_does_not_retain_empty_identifiers():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    for i in range(50):
        limiter.get_remaining(f"never-seen-{i}")
    assert len(limiter._requests) == 0


def test_rate_limiter_sweeps_expired_identifiers(monkeypatch):
    import auth_middleware.services.rate_limiter as rl

    monkeypatch.setattr(rl, "_SWEEP_THRESHOLD", 5)
    limiter = RateLimiter(max_requests=5, window_seconds=1)
    with patch("auth_middleware.services.rate_limiter.time.time", return_value=100.0):
        for i in range(10):
            limiter.is_allowed(f"ip-{i}")
    with patch("auth_middleware.services.rate_limiter.time.time", return_value=200.0):
        limiter.is_allowed("fresh")
    assert set(limiter._requests) == {"fresh"}


def test_anonymous_request_identifier_falls_back_to_the_client_ip():
    request = MagicMock(spec=Request)
    request.state = MagicMock()
    request.state.current_user = None  # what JwtAuthMiddleware sets without credentials
    request.client = MagicMock(host="10.0.0.9")
    assert _resolve_identifier(request, None) == "10.0.0.9"


def test_audit_middleware_survives_an_anonymous_request():
    app = FastAPI()

    @app.middleware("http")
    async def anonymous(request, call_next):
        request.state.current_user = None
        return await call_next(request)

    app.add_middleware(AuditMiddleware)

    @app.get("/")
    async def root():
        return {}

    assert TestClient(app).get("/").status_code == 200


@pytest.mark.asyncio
async def test_metrics_samples_are_bounded(monkeypatch):
    import auth_middleware.services.metrics as metrics

    monkeypatch.setattr(metrics, "_MAX_SAMPLES", 100)
    collector = MetricsCollector()
    for i in range(500):
        await collector.record_validation_success(float(i))
    assert len(collector._validation_times) == 100


# ------------------------------------------------------------ repository, db


@pytest.mark.asyncio
async def test_json_repository_groups_are_honoured(tmp_path, monkeypatch):
    from auth_middleware.repository import json_credentials_repository as repo
    from auth_middleware.repository.json_credentials_repository import (
        JsonCredentialsRepository,
    )

    path = tmp_path / "users.json"
    path.write_text(
        '{"bob": {"name": "Bob", "hashed_pwd": "x", "groups": ["admins"], "email": null}}'
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        repo.settings, "AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH", "users.json"
    )
    user = await JsonCredentialsRepository().get_by_id(id="bob")
    assert await user.groups == ["admins"]


def test_database_url_is_masked_in_logs():
    assert "hunter2" not in _safe_url("postgresql+asyncpg://u:hunter2@h/db")
    assert "hunter2" not in _safe_url("not a url hunter2")


# ---------------------------------------------------------------------- oidc


def _oidc(**kw) -> OidcProvider:
    return OidcProvider(
        settings=OidcProviderSettings(issuer="https://i/", audience="mine", **kw)
    )


def test_azp_does_not_override_an_aud_naming_someone_else():
    p = _oidc()
    assert not p._verify_audience({"aud": "other-api", "azp": "mine"})
    assert p._verify_audience({"client_id": "mine"})  # no aud at all: client_id counts
    assert p._verify_audience({"aud": ["x", "mine"]})


def test_forced_refresh_interval_must_be_positive():
    with pytest.raises(ValueError):
        OidcProviderSettings(
            issuer="https://i/", forced_jwks_refresh_min_interval_seconds=0
        )


# ------------------------------------------------------------- jwks cache


class CountingProvider(OidcProvider):
    def __init__(self) -> None:
        super().__init__(
            settings=OidcProviderSettings(
                issuer="https://i/",
                require_audience=False,
                jwks_background_refresh=False,
            )
        )
        self.loads = 0
        self.fail = False

    async def load_jwks(self):
        from auth_middleware.exceptions.invalid_token_exception import (
            InvalidTokenException,
        )
        from auth_middleware.types.jwt import JWKS

        self.loads += 1
        await asyncio.sleep(0.01)
        if self.fail:
            raise InvalidTokenException(status_code=401, detail="idp down")
        return JWKS(
            keys=[{"kid": "k1"}],
            timestamp=time_ns() + 3_600 * 10**9,
            usage_counter=1000,
        )


@pytest.mark.asyncio
async def test_concurrent_expiry_causes_one_reload_not_a_stampede():
    provider = CountingProvider()
    await asyncio.gather(*(provider._get_jwks() for _ in range(25)))
    assert provider.loads == 1


@pytest.mark.asyncio
async def test_stale_keys_are_served_while_the_idp_is_down_with_backoff():
    provider = CountingProvider()
    await provider._get_jwks()
    provider.jks.timestamp = 1  # expired
    provider.fail = True
    for _ in range(10):
        jwks = await provider._get_jwks()
        assert jwks is not None and jwks.keys == [{"kid": "k1"}]
    assert provider.loads == 2  # one failed retry, then the back-off holds


# --------------------------------------------------------------- middleware


def test_a_disabled_middleware_warns_loudly(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MIDDLEWARE_DISABLED", True)
    messages: list[str] = []
    sink = loguru_logger.add(lambda m: messages.append(str(m)), level="WARNING")
    try:
        JwtAuthMiddleware(FastAPI(), auth_provider=MagicMock())
    finally:
        loguru_logger.remove(sink)
    assert any("AUTH_MIDDLEWARE_DISABLED" in m for m in messages)


def test_path_prefix_without_a_leading_slash_is_refused():
    with pytest.raises(ValueError, match="path_prefix"):
        JwtAuthMiddleware(FastAPI(), auth_provider=MagicMock(), path_prefix="api")


def test_a_failing_error_responder_falls_back_to_the_default_response():
    def broken(request, failure):
        raise RuntimeError("boom")

    app = FastAPI()
    app.add_middleware(
        JwtAuthMiddleware, auth_provider=MagicMock(), error_responder=broken
    )

    @app.get("/")
    async def root():
        return {}

    r = TestClient(app, raise_server_exceptions=False).get(
        "/", headers={"Authorization": "Bearer junk"}
    )
    assert r.status_code in (401, 500) and r.json()["detail"]


def test_logger_does_not_use_loguru_diagnose_by_default():
    from auth_middleware.logging import configure_logger

    with patch("auth_middleware.logging.logger") as mock_logger:
        configure_logger({})
    assert mock_logger.add.call_args.kwargs["diagnose"] is False
    assert logging  # keep the import used


def test_audience_is_required_by_default():
    with pytest.raises(ValueError, match="require_audience"):
        OidcProvider(settings=OidcProviderSettings(issuer="https://i/"))
    OidcProvider(settings=OidcProviderSettings(issuer="https://i/", audience="mine"))


def test_unsafe_oidc_configurations_warn():
    messages: list[str] = []
    sink = loguru_logger.add(lambda m: messages.append(str(m)), level="WARNING")
    try:
        OidcProvider(
            settings=OidcProviderSettings(
                issuer="https://i/",
                require_audience=False,
                jwt_token_verification_disabled=True,
            )
        )
    finally:
        loguru_logger.remove(sink)
    joined = " ".join(messages)
    assert "without an audience" in joined
    assert "ID tokens" in joined
    assert "NOT verified" in joined
