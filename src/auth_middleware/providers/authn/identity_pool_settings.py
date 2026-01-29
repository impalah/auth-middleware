"""
Settings for AWS Cognito Identity Pool with AWS credentials support.

This module provides configuration for Identity Pool integration, allowing
JWT token exchange for temporary AWS credentials.
"""

from pydantic import model_validator

from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)


class IdentityPoolSettings(CognitoAuthzProviderSettings):
    """Settings for Cognito Identity Pool with AWS credentials support.

    Extends CognitoAuthzProviderSettings to add Identity Pool configuration,
    enabling JWT token exchange for temporary AWS credentials.

    Attributes:
        identity_pool_id: AWS Cognito Identity Pool ID
        identity_pool_region: AWS region for Identity Pool (defaults to user_pool_region)
        enable_aws_credentials: Whether to enable AWS credentials exchange
        credentials_duration_seconds: Duration for temporary AWS credentials (max 3600)

    Example:
        ```python
        from auth_middleware.providers.authn.identity_pool_settings import (
            IdentityPoolSettings
        )

        settings = IdentityPoolSettings(
            user_pool_id="us-east-1_abcd1234",
            user_pool_region="us-east-1",
            identity_pool_id="us-east-1:12345678-1234-1234-1234-123456789012",
            enable_aws_credentials=True,
        )
        ```
    """

    # Identity Pool configuration
    identity_pool_id: str
    identity_pool_region: str | None = None

    # AWS Credentials configuration
    enable_aws_credentials: bool = True
    credentials_duration_seconds: int = 3600  # 1 hour (max allowed)

    @model_validator(mode="before")
    @classmethod
    def set_default_region(cls, data):
        """Set identity_pool_region to user_pool_region if not specified."""
        if isinstance(data, dict):
            if data.get("identity_pool_region") is None and "user_pool_region" in data:
                data["identity_pool_region"] = data["user_pool_region"]
        return data

    @model_validator(mode="after")
    def validate_credentials_duration(self):
        """Validate credentials duration is within AWS limits."""
        if self.credentials_duration_seconds > 3600:
            raise ValueError("credentials_duration_seconds cannot exceed 3600 (1 hour)")

        if self.credentials_duration_seconds < 900:
            raise ValueError(
                "credentials_duration_seconds must be at least 900 (15 minutes)"
            )

        return self
