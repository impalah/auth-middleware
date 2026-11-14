"""Hardening options of OidcProvider + a hostile-token battery run end to end.

The battery mirrors the attack classes of a production verification (alg none,
algorithm confusion, key-id tricks, wrong claims, malformed segments...), driven
through ``JwtAuthMiddleware`` + a local fake JWKS so no network is involved.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from collections.abc import Callable
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey

from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
from auth_middleware.providers.oidc.oidc_provider import OidcProvider
from auth_middleware.providers.oidc.oidc_provider_settings import OidcProviderSettings
from auth_middleware.providers.oidc.token_type import TokenType
from auth_middleware.settings import settings as global_settings
from auth_middleware.types.jwt import JWTAuthorizationCredentials

ISSUER = "https://idp.example.com/pool/"
AUDIENCE = "my-client"


def _segment(value: Any) -> str:
    raw = (
        value
        if isinstance(value, bytes)
        else json.dumps(value, separators=(",", ":")).encode()
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Idp:
    """A fake identity provider: one signing key, a JWKS, a fetch counter."""

    def __init__(self) -> None:
        self.key = RSAKey.generate_key(2048, auto_kid=True)
        self.extra_jwks: list[dict[str, Any]] = []
        self.fetches = 0

    def jwks(self) -> list[dict[str, Any]]:
        return [self.key.as_dict(private=False), *self.extra_jwks]

    def access_claims(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "iss": ISSUER,
            "sub": "user-1",
            "client_id": AUDIENCE,
            "token_use": "access",
            "username": "una",
            "exp": int(time.time()) + 3600,
        }
        base.update(overrides)
        return {k: v for k, v in base.items() if v is not None}

    def sign(self, claims: dict[str, Any], header: dict[str, Any] | None = None) -> str:
        return jwt.encode(
            {"alg": "RS256", "kid": self.key.kid, **(header or {})}, claims, self.key
        )


class FakeJwksProvider(OidcProvider):
    def __init__(self, idp: Idp, settings: OidcProviderSettings) -> None:
        super().__init__(settings=settings)
        self.idp = idp

    async def get_keys(self) -> list[Any]:
        self.idp.fetches += 1
        return self.idp.jwks()


def hardened_settings(**extra: Any) -> OidcProviderSettings:
    return OidcProviderSettings(
        issuer=ISSUER,
        audience=AUDIENCE,
        require_audience=True,
        accepted_token_types=frozenset({TokenType.ACCESS}),
        forced_jwks_refresh_min_interval_seconds=30.0,
        **extra,
    )


class World:
    def __init__(self) -> None:
        self.idp = Idp()
        self.provider = FakeJwksProvider(self.idp, hardened_settings())
        app = FastAPI()
        app.add_middleware(
            JwtAuthMiddleware,
            auth_provider=self.provider,
            canonical_bearer_scheme=True,
            strict=True,
        )

        @app.get("/ping")
        async def ping(request: Request) -> dict[str, str]:
            return {"sub": request.state.current_user.id}

        self.client = TestClient(app, raise_server_exceptions=False)

    def claims(self, **overrides: Any) -> dict[str, Any]:
        return self.idp.access_claims(**overrides)

    def get(self, token: str) -> Any:
        return self.client.get(
            "/ping",
            headers={"Authorization": b"Bearer " + token.encode("latin-1", "replace")},
        )


@pytest.fixture
def world() -> World:
    return World()


def _unsigned(claims: dict[str, Any], header: dict[str, Any]) -> str:
    return f"{_segment(header)}.{_segment(claims)}."


def _other_key(claims: dict[str, Any], header: dict[str, Any] | None = None) -> str:
    key = RSAKey.generate_key(2048, auto_kid=True)
    return jwt.encode({"alg": "RS256", "kid": key.kid, **(header or {})}, claims, key)


def _hs256_with_public_key(w: World) -> str:
    """Classic algorithm confusion, forged by hand (joserfc refuses to build it)."""
    import hashlib
    import hmac

    pem = w.idp.key.as_pem(private=False)
    signing_input = (
        f"{_segment({'alg': 'HS256', 'kid': w.idp.key.kid})}.{_segment(w.claims())}"
    )
    mac = hmac.new(pem, signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{_segment(mac)}"


def _hs256_with_jwks_oct_key(w: World) -> str:
    symmetric = OctKey.generate_key(256, auto_kid=True)
    w.idp.extra_jwks.append(symmetric.as_dict())
    return jwt.encode({"alg": "HS256", "kid": symmetric.kid}, w.claims(), symmetric)


HOSTILE: dict[str, Callable[[World], str]] = {
    "alg none": lambda w: _unsigned(w.claims(), {"alg": "none", "typ": "JWT"}),
    "alg None (case)": lambda w: _unsigned(w.claims(), {"alg": "None"}),
    "alg none with a signature part": lambda w: (
        _unsigned(w.claims(), {"alg": "none"}) + "AAAA"
    ),
    "HS256 signed with the public key": _hs256_with_public_key,
    "HS256 with a symmetric key the JWKS offers": _hs256_with_jwks_oct_key,
    "no kid": lambda w: jwt.encode({"alg": "RS256"}, w.claims(), w.idp.key),
    "unknown kid": lambda w: w.idp.sign(w.claims(), {"kid": "not-in-the-jwks"}),
    "signed by another key": lambda w: _other_key(w.claims()),
    "expired": lambda w: w.idp.sign(w.claims(exp=int(time.time()) - 3600)),
    "nbf in the future": lambda w: w.idp.sign(w.claims(nbf=int(time.time()) + 3600)),
    "no exp": lambda w: w.idp.sign(w.claims(exp=None)),
    "wrong issuer": lambda w: w.idp.sign(w.claims(iss="https://evil.example.test/")),
    "wrong audience (client_id)": lambda w: w.idp.sign(w.claims(client_id="other")),
    "ID token used as an access token": lambda w: w.idp.sign(
        w.claims(token_use="id", email="x@example.com", aud=AUDIENCE)
    ),
    "no token_use, identity claims only": lambda w: w.idp.sign(
        w.claims(token_use=None, aud=AUDIENCE)
    ),
    "empty-scope token with unknown type": lambda w: w.idp.sign(
        w.claims(token_use=None, username=None, client_id=None, aud=AUDIENCE)
    ),
    "refresh token (token_use=refresh)": lambda w: w.idp.sign(
        w.claims(token_use="refresh")
    ),
    "jku pointing at the attacker": lambda w: _other_key(
        w.claims(), {"jku": "https://evil.example.test/jwks.json"}
    ),
    "x5u pointing at the attacker": lambda w: _other_key(
        w.claims(), {"x5u": "https://evil.example.test/cert.pem"}
    ),
    "embedded jwk header": lambda w: jwt.encode(
        {"alg": "RS256", "jwk": RSAKey.generate_key(2048).as_dict(private=False)},
        w.claims(),
        RSAKey.generate_key(2048, auto_kid=True),
    ),
    "two segments": lambda w: "aaa.bbb",
    "four segments": lambda w: "aaa.bbb.ccc.ddd",
    "only dots": lambda w: "....",
    "empty segments": lambda w: "..",
    "not base64": lambda w: "%%%.%%%.%%%",
    "header is not JSON": lambda w: (
        f"{_segment(b'not json')}.{_segment(w.claims())}.AAAA"
    ),
    "payload is not JSON": lambda w: (
        f"{_segment({'alg': 'RS256'})}.{_segment(b'nope')}.AAAA"
    ),
    "payload is a JSON array": lambda w: (
        f"{_segment({'alg': 'RS256'})}.{_segment([1, 2])}.AAAA"
    ),
    "header is a JSON string": lambda w: (
        f"{_segment('RS256')}.{_segment(w.claims())}.AAAA"
    ),
    "control characters": lambda w: "a\x00b.c\x01d.e\x02f",
    "latin-1 bytes": lambda w: "\xe9\xe9.\xf1\xf1.\xe7\xe7",
    "oversized garbage (200 KB)": lambda w: "x" * 200_000 + ".y.z",
}


def test_the_battery_is_not_empty():
    assert len(HOSTILE) >= 25


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_hostile_token_is_401_and_says_nothing(world, name):
    token = HOSTILE[name](world)
    response = world.get(token)
    assert response.status_code == 401, f"{name}: {response.status_code}"
    assert response.json() == {"detail": "Invalid token"}
    assert token.lower() not in response.text.lower()


def test_the_control_a_valid_access_token_passes(world):
    for scheme in ("Bearer", "bearer", "BEARER"):
        token = world.idp.sign(world.claims())
        r = world.client.get("/ping", headers={"Authorization": f"{scheme} {token}"})
        assert r.status_code == 200 and r.json() == {"sub": "user-1"}


def test_a_well_formed_signed_token_with_200kb_of_claims_never_causes_a_500(world):
    """The library sets no size cap (servers/proxies do); it must not crash."""
    response = world.get(world.idp.sign(world.claims(pad="x" * 200_000)))
    assert response.status_code in (200, 401, 413)


def test_key_rotation_is_accepted_after_one_forced_refresh(world):
    assert world.get(world.idp.sign(world.claims())).status_code == 200
    fetches = world.idp.fetches
    world.idp.key = RSAKey.generate_key(2048, auto_kid=True)  # rotation
    assert world.get(world.idp.sign(world.claims())).status_code == 200
    assert world.idp.fetches == fetches + 1


def test_forged_kids_cause_at_most_one_fetch_per_interval(world):
    world.get(world.idp.sign(world.claims()))
    before = world.idp.fetches
    for i in range(25):
        r = world.get(world.idp.sign(world.claims(), {"kid": f"forged-{i}"}))
        assert r.status_code == 401
    assert world.idp.fetches - before <= 1


# -- forced refresh details -------------------------------------------------


def _creds(token: str) -> JWTAuthorizationCredentials:
    header, payload, sig = token.split(".")

    def dec(part: str) -> dict[str, Any]:
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))

    return JWTAuthorizationCredentials(
        jwt_token=token,
        header=dec(header),
        claims=dec(payload),
        signature=sig,
        message=f"{header}.{payload}",
    )


@pytest.mark.asyncio
async def test_concurrent_unknown_kid_requests_share_one_refresh():
    idp = Idp()
    provider = FakeJwksProvider(idp, hardened_settings())
    await provider.verify_token(_creds(idp.sign(idp.access_claims())))
    idp.key = RSAKey.generate_key(2048, auto_kid=True)
    token = _creds(idp.sign(idp.access_claims()))
    before = idp.fetches
    results = await asyncio.gather(*(provider.verify_token(token) for _ in range(10)))
    assert all(results)
    assert idp.fetches - before == 1


@pytest.mark.asyncio
async def test_the_throttle_is_per_instance_not_shared():
    idp_a, idp_b = Idp(), Idp()
    a = FakeJwksProvider(idp_a, hardened_settings())
    b = FakeJwksProvider(idp_b, hardened_settings())
    for provider, idp in ((a, idp_a), (b, idp_b)):
        await provider.verify_token(_creds(idp.sign(idp.access_claims())))
        idp.key = RSAKey.generate_key(2048, auto_kid=True)
        assert await provider.verify_token(_creds(idp.sign(idp.access_claims())))
        assert idp.fetches == 2  # each instance got its own forced refresh


@pytest.mark.asyncio
async def test_token_without_kid_never_triggers_a_refresh():
    idp = Idp()
    provider = FakeJwksProvider(idp, hardened_settings())
    await provider.verify_token(_creds(idp.sign(idp.access_claims())))
    before = idp.fetches
    token = _creds(jwt.encode({"alg": "RS256"}, idp.access_claims(), idp.key))
    with pytest.raises(InvalidTokenException):
        await provider.verify_token(token)
    assert idp.fetches == before


@pytest.mark.asyncio
async def test_default_never_forces_a_refresh():
    idp = Idp()
    provider = FakeJwksProvider(
        idp, OidcProviderSettings(issuer=ISSUER, require_audience=False)
    )
    await provider.verify_token(_creds(idp.sign(idp.access_claims())))
    before = idp.fetches
    with pytest.raises(InvalidTokenException):
        await provider.verify_token(
            _creds(idp.sign(idp.access_claims(), {"kid": "forged"}))
        )
    assert idp.fetches == before


# -- audience, token types, strict -----------------------------------------


def test_require_audience_refuses_to_build_without_one():
    with pytest.raises(ValueError, match="require_audience"):
        OidcProvider(
            settings=OidcProviderSettings(issuer=ISSUER, require_audience=True)
        )
    OidcProvider(
        settings=OidcProviderSettings(
            issuer=ISSUER, require_audience=True, audience=AUDIENCE
        )
    )


@pytest.mark.asyncio
async def test_audience_mismatch_and_missing_are_rejected_when_required():
    idp = Idp()
    provider = FakeJwksProvider(idp, hardened_settings())
    assert await provider.verify_token(_creds(idp.sign(idp.access_claims())))
    for claims in (
        idp.access_claims(client_id="other"),
        idp.access_claims(client_id=None),
    ):
        assert not await provider.verify_token(_creds(idp.sign(claims)))
    provider._settings.__dict__["audience"] = None  # settings mutated after build
    assert not provider._verify_audience(idp.access_claims())


@pytest.mark.asyncio
async def test_accepted_token_types_access_only():
    idp = Idp()
    provider = FakeJwksProvider(idp, hardened_settings())
    assert await provider.verify_token(_creds(idp.sign(idp.access_claims())))
    for claims in (
        idp.access_claims(token_use="id", email="a@example.com"),
        idp.access_claims(token_use="refresh"),
        idp.access_claims(token_use=None, username=None, client_id=None, aud=AUDIENCE),
    ):
        assert not await provider.verify_token(_creds(idp.sign(claims)))


@pytest.mark.asyncio
async def test_defaults_keep_historical_behaviour():
    idp = Idp()
    provider = FakeJwksProvider(
        idp, OidcProviderSettings(issuer=ISSUER, require_audience=False)
    )
    # no audience configured: accepted; ID token: accepted; refresh: rejected
    assert await provider.verify_token(_creds(idp.sign(idp.access_claims())))
    assert await provider.verify_token(
        _creds(idp.sign(idp.access_claims(token_use="id", email="a@example.com")))
    )
    assert not await provider.verify_token(
        _creds(idp.sign(idp.access_claims(token_use="refresh")))
    )


def test_strict_refuses_the_disabled_flag_and_disabled_verification(monkeypatch):
    provider = OidcProvider(
        settings=OidcProviderSettings(issuer=ISSUER, require_audience=False)
    )
    JwtAuthMiddleware(FastAPI(), auth_provider=provider, strict=True)
    monkeypatch.setattr(global_settings, "AUTH_MIDDLEWARE_DISABLED", True)
    with pytest.raises(RuntimeError, match="AUTH_MIDDLEWARE_DISABLED"):
        JwtAuthMiddleware(FastAPI(), auth_provider=provider, strict=True)
    JwtAuthMiddleware(FastAPI(), auth_provider=provider)  # default: unchanged
    monkeypatch.setattr(global_settings, "AUTH_MIDDLEWARE_DISABLED", False)
    unsafe = OidcProvider(
        settings=OidcProviderSettings(
            issuer=ISSUER, require_audience=False, jwt_token_verification_disabled=True
        )
    )
    with pytest.raises(RuntimeError, match="verification"):
        JwtAuthMiddleware(FastAPI(), auth_provider=unsafe, strict=True)
