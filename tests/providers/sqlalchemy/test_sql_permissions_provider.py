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
