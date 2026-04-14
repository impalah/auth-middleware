"""Tests for SqlGroupsProvider."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_middleware.providers.authz.sql_groups_provider import (
    GroupsModel,
    SqlGroupsProvider,
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


def _mock_session(rows: list[GroupsModel]):
    """Return a mock AsyncDatabase.get_session() context manager yielding a session."""
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = rows

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    @asynccontextmanager
    async def _get_session():
        yield mock_session

    return _get_session


class TestSqlGroupsProviderFetchGroups:
    @pytest.mark.asyncio
    async def test_fetch_groups_from_jwt_credentials(self):
        provider = SqlGroupsProvider()
        token = _make_token("alice")

        row = GroupsModel()
        row.group = "admin"

        with patch(
            "auth_middleware.providers.authz.sql_groups_provider.AsyncDatabase.get_session",
            _mock_session([row]),
        ):
            result = await provider.fetch_groups(token)

        assert result == ["admin"]

    @pytest.mark.asyncio
    async def test_fetch_groups_from_plain_string(self):
        provider = SqlGroupsProvider()

        row = GroupsModel()
        row.group = "editors"

        with patch(
            "auth_middleware.providers.authz.sql_groups_provider.AsyncDatabase.get_session",
            _mock_session([row]),
        ):
            result = await provider.fetch_groups("bob")

        assert result == ["editors"]

    @pytest.mark.asyncio
    async def test_fetch_groups_returns_empty_list(self):
        provider = SqlGroupsProvider()
        token = _make_token("unknown")

        with patch(
            "auth_middleware.providers.authz.sql_groups_provider.AsyncDatabase.get_session",
            _mock_session([]),
        ):
            result = await provider.fetch_groups(token)

        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_groups_multiple_groups(self):
        provider = SqlGroupsProvider()

        rows = []
        for g in ["admin", "staff", "viewers"]:
            m = GroupsModel()
            m.group = g
            rows.append(m)

        with patch(
            "auth_middleware.providers.authz.sql_groups_provider.AsyncDatabase.get_session",
            _mock_session(rows),
        ):
            result = await provider.fetch_groups("carol")

        assert result == ["admin", "staff", "viewers"]

    @pytest.mark.asyncio
    async def test_get_groups_propagates_db_exception(self):
        provider = SqlGroupsProvider()

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=RuntimeError("db down"))

        @asynccontextmanager
        async def _failing_session():
            yield mock_session

        with patch(
            "auth_middleware.providers.authz.sql_groups_provider.AsyncDatabase.get_session",
            _failing_session,
        ):
            with pytest.raises(RuntimeError, match="db down"):
                await provider.get_groups_from_db(username="dave")
