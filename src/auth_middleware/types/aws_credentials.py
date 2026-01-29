"""
AWS Credentials model for temporary credentials from Cognito Identity Pool.

This module provides the data model for AWS temporary credentials obtained
through Cognito Identity Pool's GetCredentialsForIdentity operation.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AWSCredentials(BaseModel):
    """Temporary AWS credentials from Cognito Identity Pool.

    These credentials are obtained by exchanging a JWT token from Cognito User Pool
    for temporary AWS credentials via Cognito Identity Pool.

    Attributes:
        access_key_id: AWS access key ID
        secret_access_key: AWS secret access key
        session_token: AWS session token for temporary credentials
        expiration: Expiration time of the credentials (UTC)
        identity_id: Cognito Identity ID associated with these credentials

    Example:
        ```python
        from datetime import datetime, timezone

        credentials = AWSCredentials(
            access_key_id="ASIAX...",
            secret_access_key="secret...",
            session_token="FwoGZXIv...",
            expiration=datetime(2026, 1, 29, 15, 0, 0, tzinfo=timezone.utc),
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        # Use with boto3
        import boto3
        s3 = boto3.client(
            's3',
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,
        )
        ```
    """

    model_config = ConfigDict(
        frozen=True,  # Make immutable
        json_schema_extra={
            "example": {
                "access_key_id": "ASIAXAMPLEXAMPLEXA",
                "secret_access_key": "secretaccesskeyexamplesecretaccesskeyexample",
                "session_token": "FwoGZXIvYXdzEBExample//////////SessionTokenExample",
                "expiration": "2026-01-29T15:00:00Z",
                "identity_id": "us-east-1:12345678-1234-1234-1234-123456789012",
            }
        },
    )

    access_key_id: str = Field(
        ...,
        description="AWS access key ID for temporary credentials",
        min_length=16,
        max_length=128,
    )

    secret_access_key: str = Field(
        ...,
        description="AWS secret access key",
        min_length=40,
    )

    session_token: str = Field(
        ...,
        description="Session token for temporary credentials",
        min_length=100,
    )

    expiration: datetime = Field(
        ...,
        description="Expiration time of the credentials (UTC)",
    )

    identity_id: str = Field(
        ...,
        description="Cognito Identity ID (format: region:uuid)",
        pattern=r"^[a-z]{2}-[a-z]+-\d:\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$",
    )

    def is_expired(self) -> bool:
        """Check if credentials are expired.

        Returns:
            True if credentials are expired, False otherwise

        Example:
            ```python
            if credentials.is_expired():
                # Refresh credentials
                credentials = await provider.get_aws_credentials(token)
            ```
        """
        return datetime.now(self.expiration.tzinfo) >= self.expiration

    def time_until_expiration(self) -> float:
        """Get seconds until expiration.

        Returns:
            Number of seconds until expiration (negative if already expired)

        Example:
            ```python
            if credentials.time_until_expiration() < 300:  # Less than 5 minutes
                # Refresh credentials proactively
                credentials = await provider.get_aws_credentials(token)
            ```
        """
        delta = self.expiration - datetime.now(self.expiration.tzinfo)
        return delta.total_seconds()

    def to_boto3_dict(self) -> dict[str, str]:
        """Convert to dict suitable for boto3 client initialization.

        Returns:
            Dictionary with boto3 credential keys

        Example:
            ```python
            import boto3

            credentials = await provider.get_aws_credentials(token)
            s3 = boto3.client('s3', **credentials.to_boto3_dict())
            ```
        """
        return {
            "aws_access_key_id": self.access_key_id,
            "aws_secret_access_key": self.secret_access_key,
            "aws_session_token": self.session_token,
        }
