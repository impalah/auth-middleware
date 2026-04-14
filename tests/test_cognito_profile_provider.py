"""Tests for CognitoProfileProvider."""

from unittest.mock import MagicMock, patch

import pytest

from auth_middleware.providers.profile.cognito_profile_provider import (
    CognitoProfileProvider,
)


class TestCognitoProfileProviderInit:
    def test_uses_provided_boto_client(self):
        """When boto_client is given, it should be used directly."""
        mock_client = MagicMock()
        provider = CognitoProfileProvider(
            user_pool_id="us-east-1_ABC",
            region_name="us-east-1",
            boto_client=mock_client,
        )
        assert provider._client is mock_client

    def test_creates_boto3_client_when_not_provided(self):
        """Without boto_client, boto3.client is called lazily."""
        mock_client = MagicMock()
        mock_boto3 = MagicMock(return_value=mock_client)
        mock_boto3_module = MagicMock()
        mock_boto3_module.client = mock_boto3
        with patch.dict("sys.modules", {"boto3": mock_boto3_module}):
            # Re-execute the __init__ path that imports boto3
            provider = CognitoProfileProvider(
                user_pool_id="us-east-1_ABC",
                region_name="eu-west-1",
            )
        mock_boto3.assert_called_once_with(
            "cognito-idp", region_name="eu-west-1"
        )
        assert provider._client is mock_client


class TestFetchProfile:
    @pytest.mark.asyncio
    async def test_returns_attributes_dict(self):
        """Happy path: admin_get_user returns attributes."""
        mock_client = MagicMock()
        mock_client.admin_get_user.return_value = {
            "UserAttributes": [
                {"Name": "sub", "Value": "user-123"},
                {"Name": "email", "Value": "user@example.com"},
                {"Name": "custom:role", "Value": "admin"},
            ]
        }
        provider = CognitoProfileProvider(
            user_pool_id="us-east-1_ABC",
            region_name="us-east-1",
            boto_client=mock_client,
        )
        result = await provider.fetch_profile("user-123")
        assert result == {
            "sub": "user-123",
            "email": "user@example.com",
            "custom:role": "admin",
        }

    @pytest.mark.asyncio
    async def test_returns_empty_dict_when_no_attributes(self):
        """When UserAttributes is empty, return empty dict."""
        mock_client = MagicMock()
        mock_client.admin_get_user.return_value = {"UserAttributes": []}
        provider = CognitoProfileProvider(
            user_pool_id="us-east-1_ABC",
            region_name="us-east-1",
            boto_client=mock_client,
        )
        result = await provider.fetch_profile("user-123")
        assert result == {}

    @pytest.mark.asyncio
    async def test_returns_empty_dict_on_user_not_found(self):
        """UserNotFoundException should return empty dict."""
        mock_exc = Exception("User not found")
        mock_exc.response = {"Error": {"Code": "UserNotFoundException"}}  # type: ignore[attr-defined]
        mock_client = MagicMock()
        mock_client.admin_get_user.side_effect = mock_exc
        provider = CognitoProfileProvider(
            user_pool_id="us-east-1_ABC",
            region_name="us-east-1",
            boto_client=mock_client,
        )
        result = await provider.fetch_profile("missing-user")
        assert result == {}

    @pytest.mark.asyncio
    async def test_returns_empty_dict_on_generic_exception(self):
        """Any other exception should also return empty dict."""
        mock_client = MagicMock()
        mock_client.admin_get_user.side_effect = Exception("Connection error")
        provider = CognitoProfileProvider(
            user_pool_id="us-east-1_ABC",
            region_name="us-east-1",
            boto_client=mock_client,
        )
        result = await provider.fetch_profile("user-123")
        assert result == {}

    @pytest.mark.asyncio
    async def test_returns_empty_dict_on_exception_without_response_attr(self):
        """Exception without .response attribute returns empty dict (not UserNotFoundException branch)."""
        mock_client = MagicMock()
        mock_client.admin_get_user.side_effect = RuntimeError("unexpected")
        provider = CognitoProfileProvider(
            user_pool_id="us-east-1_ABC",
            region_name="us-east-1",
            boto_client=mock_client,
        )
        result = await provider.fetch_profile("user-123")
        assert result == {}

    @pytest.mark.asyncio
    async def test_calls_admin_get_user_with_correct_args(self):
        """admin_get_user must be called with pool id and username."""
        mock_client = MagicMock()
        mock_client.admin_get_user.return_value = {"UserAttributes": []}
        provider = CognitoProfileProvider(
            user_pool_id="us-east-1_MYPOOL",
            region_name="us-east-1",
            boto_client=mock_client,
        )
        await provider.fetch_profile("someone")
        mock_client.admin_get_user.assert_called_once_with(
            UserPoolId="us-east-1_MYPOOL",
            Username="someone",
        )
