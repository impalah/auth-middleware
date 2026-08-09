"""Tests for SqlGroupsProvider."""

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_middleware.providers.sqlalchemy.sql_groups_provider import (
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
            "auth_middleware.providers.sqlalchemy.sql_groups_provider.AsyncDatabase.get_session",
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
            "auth_middleware.providers.sqlalchemy.sql_groups_provider.AsyncDatabase.get_session",
            _mock_session([row]),
        ):
            result = await provider.fetch_groups("bob")

        assert result == ["editors"]

    @pytest.mark.asyncio
    async def test_fetch_groups_returns_empty_list(self):
        provider = SqlGroupsProvider()
        token = _make_token("unknown")

        with patch(
            "auth_middleware.providers.sqlalchemy.sql_groups_provider.AsyncDatabase.get_session",
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
            "auth_middleware.providers.sqlalchemy.sql_groups_provider.AsyncDatabase.get_session",
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
            "auth_middleware.providers.sqlalchemy.sql_groups_provider.AsyncDatabase.get_session",
            _failing_session,
        ):
            with pytest.raises(RuntimeError, match="db down"):
                await provider.get_groups_from_db(username="dave")


class TestSqlGroupsProviderIdClaim:
    @pytest.mark.asyncio
    async def test_raises_clear_error_when_default_username_claim_missing(self):
        # e.g. an Entra ID / OIDC token, which has no "username" claim
        provider = SqlGroupsProvider()
        token = JWTAuthorizationCredentials(
            jwt_token="h.p.s",
            header={"alg": "RS256"},
            claims={"sub": "u1", "preferred_username": "alice"},
            signature="s",
            message="h.p",
        )

        with pytest.raises(ValueError, match="username"):
            await provider.fetch_groups(token)

    @pytest.mark.asyncio
    async def test_uses_configured_id_claim(self):
        provider = SqlGroupsProvider(id_claim="preferred_username")
        token = JWTAuthorizationCredentials(
            jwt_token="h.p.s",
            header={"alg": "RS256"},
            claims={"sub": "u1", "preferred_username": "alice"},
            signature="s",
            message="h.p",
        )

        row = GroupsModel()
        row.group = "admin"

        with patch(
            "auth_middleware.providers.sqlalchemy.sql_groups_provider.AsyncDatabase.get_session",
            _mock_session([row]),
        ):
            result = await provider.fetch_groups(token)

        assert result == ["admin"]

    @pytest.mark.asyncio
    async def test_configured_id_claim_looks_up_by_that_claims_value(self):
        provider = SqlGroupsProvider(id_claim="sub")
        provider.get_groups_from_db = AsyncMock(return_value=["admin"])
        token = JWTAuthorizationCredentials(
            jwt_token="h.p.s",
            header={"alg": "RS256"},
            claims={"sub": "user-uuid-123", "preferred_username": "alice"},
            signature="s",
            message="h.p",
        )

        result = await provider.fetch_groups(token)

        provider.get_groups_from_db.assert_awaited_once_with(username="user-uuid-123")
        assert result == ["admin"]
