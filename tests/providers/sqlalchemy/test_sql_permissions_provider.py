"""Tests for SqlPermissionsProvider."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_middleware.providers.sqlalchemy.sql_permissions_provider import (
    PermissionsModel,
    SqlPermissionsProvider,
)
from auth_middleware.types.jwt import JWTAuthorizationCredentials


def _make_token(username: str) -> JWTAuthorizationCredentials:
    return JWTAuthorizationCredentials(
        jwt_token="h.p.s",
        header={"alg": "HS256"},
        claims={"username": username, "sub": username},
        signature="s",
        message="h.p",
    )


def _mock_session(rows: list[PermissionsModel]):
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = rows

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    @asynccontextmanager
    async def _get_session():
        yield mock_session

    return _get_session


class TestSqlPermissionsProviderFetchPermissions:
    @pytest.mark.asyncio
    async def test_fetch_permissions_from_jwt_credentials(self):
        provider = SqlPermissionsProvider()
        token = _make_token("alice")

        row = PermissionsModel()
        row.permission = "read"

        with patch(
            "auth_middleware.providers.sqlalchemy.sql_permissions_provider.AsyncDatabase.get_session",
            _mock_session([row]),
        ):
            result = await provider.fetch_permissions(token)

        assert result == ["read"]

    @pytest.mark.asyncio
    async def test_fetch_permissions_from_plain_string(self):
        provider = SqlPermissionsProvider()

        row = PermissionsModel()
        row.permission = "write"

        with patch(
            "auth_middleware.providers.sqlalchemy.sql_permissions_provider.AsyncDatabase.get_session",
            _mock_session([row]),
        ):
            result = await provider.fetch_permissions("bob")

        assert result == ["write"]

    @pytest.mark.asyncio
    async def test_fetch_permissions_returns_empty_list(self):
        provider = SqlPermissionsProvider()
        token = _make_token("unknown")

        with patch(
            "auth_middleware.providers.sqlalchemy.sql_permissions_provider.AsyncDatabase.get_session",
            _mock_session([]),
        ):
            result = await provider.fetch_permissions(token)

        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_permissions_multiple(self):
        provider = SqlPermissionsProvider()

        rows = []
        for p in ["read", "write", "delete"]:
            m = PermissionsModel()
            m.permission = p
            rows.append(m)

        with patch(
            "auth_middleware.providers.sqlalchemy.sql_permissions_provider.AsyncDatabase.get_session",
            _mock_session(rows),
        ):
            result = await provider.fetch_permissions("carol")

        assert result == ["read", "write", "delete"]

    @pytest.mark.asyncio
    async def test_get_permissions_propagates_db_exception(self):
        provider = SqlPermissionsProvider()

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=RuntimeError("db down"))

        @asynccontextmanager
        async def _failing_session():
            yield mock_session

        with patch(
            "auth_middleware.providers.sqlalchemy.sql_permissions_provider.AsyncDatabase.get_session",
            _failing_session,
        ):
            with pytest.raises(RuntimeError, match="db down"):
                await provider.get_permissions_from_db(username="dave")


class TestSqlPermissionsProviderIdClaim:
    @pytest.mark.asyncio
    async def test_raises_clear_error_when_default_username_claim_missing(self):
        # e.g. an Entra ID / OIDC token, which has no "username" claim
        provider = SqlPermissionsProvider()
        token = JWTAuthorizationCredentials(
            jwt_token="h.p.s",
            header={"alg": "RS256"},
            claims={"sub": "u1", "preferred_username": "alice"},
            signature="s",
            message="h.p",
        )

        with pytest.raises(ValueError, match="username"):
            await provider.fetch_permissions(token)

    @pytest.mark.asyncio
    async def test_uses_configured_id_claim(self):
        provider = SqlPermissionsProvider(id_claim="preferred_username")
        token = JWTAuthorizationCredentials(
            jwt_token="h.p.s",
            header={"alg": "RS256"},
            claims={"sub": "u1", "preferred_username": "alice"},
            signature="s",
            message="h.p",
        )

        row = PermissionsModel()
        row.permission = "read"

        with patch(
            "auth_middleware.providers.sqlalchemy.sql_permissions_provider.AsyncDatabase.get_session",
            _mock_session([row]),
        ):
            result = await provider.fetch_permissions(token)

        assert result == ["read"]

    @pytest.mark.asyncio
    async def test_configured_id_claim_looks_up_by_that_claims_value(self):
        provider = SqlPermissionsProvider(id_claim="sub")
        provider.get_permissions_from_db = AsyncMock(return_value=["read"])
        token = JWTAuthorizationCredentials(
            jwt_token="h.p.s",
            header={"alg": "RS256"},
            claims={"sub": "user-uuid-123", "preferred_username": "alice"},
            signature="s",
            message="h.p",
        )

        result = await provider.fetch_permissions(token)

        provider.get_permissions_from_db.assert_awaited_once_with(
            username="user-uuid-123"
        )
        assert result == ["read"]
