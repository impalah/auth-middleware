"""Tests for AWS Credentials model."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from auth_middleware.types.aws_credentials import AWSCredentials


class TestAWSCredentials:
    """Test suite for AWSCredentials model."""

    def test_basic_initialization(self):
        """Test basic credentials initialization."""
        expiration = datetime.now(UTC) + timedelta(hours=1)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        assert credentials.access_key_id == "ASIAXAMPLEXAMPLEXA"
        assert (
            credentials.secret_access_key
            == "secretaccesskeyexamplesecretaccesskeyexample"
        )
        assert (
            credentials.identity_id == "us-east-1:12345678-1234-1234-1234-123456789012"
        )
        assert credentials.expiration == expiration

    def test_is_expired_false(self):
        """Test is_expired returns False for valid credentials."""
        expiration = datetime.now(UTC) + timedelta(hours=1)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        assert credentials.is_expired() is False

    def test_is_expired_true(self):
        """Test is_expired returns True for expired credentials."""
        expiration = datetime.now(UTC) - timedelta(hours=1)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        assert credentials.is_expired() is True

    def test_time_until_expiration_positive(self):
        """Test time_until_expiration returns positive value for valid credentials."""
        expiration = datetime.now(UTC) + timedelta(hours=1)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        time_left = credentials.time_until_expiration()
        assert time_left > 3500  # Close to 1 hour
        assert time_left < 3700

    def test_time_until_expiration_negative(self):
        """Test time_until_expiration returns negative value for expired credentials."""
        expiration = datetime.now(UTC) - timedelta(hours=1)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        time_left = credentials.time_until_expiration()
        assert time_left < 0

    def test_to_boto3_dict(self):
        """Test conversion to boto3-compatible dict."""
        expiration = datetime.now(UTC) + timedelta(hours=1)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        boto3_dict = credentials.to_boto3_dict()

        assert boto3_dict == {
            "aws_access_key_id": "ASIAXAMPLEXAMPLEXA",
            "aws_secret_access_key": "secretaccesskeyexamplesecretaccesskeyexample",
            "aws_session_token": "FwoGZXIvYXdzEBExample" + "x" * 100,
        }

    def test_immutability(self):
        """Test that credentials are immutable (frozen)."""
        expiration = datetime.now(UTC) + timedelta(hours=1)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        with pytest.raises(ValidationError):
            credentials.access_key_id = "NEWKEY"

    def test_access_key_too_short(self):
        """Test validation error when access key is too short."""
        with pytest.raises(ValidationError, match="at least 16 characters"):
            AWSCredentials(
                access_key_id="TOOSHORT",
                secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
                session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
                expiration=datetime.now(UTC) + timedelta(hours=1),
                identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
            )

    def test_secret_access_key_too_short(self):
        """Test validation error when secret key is too short."""
        with pytest.raises(ValidationError, match="at least 40 characters"):
            AWSCredentials(
                access_key_id="ASIAXAMPLEXAMPLEXA",
                secret_access_key="tooshort",
                session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
                expiration=datetime.now(UTC) + timedelta(hours=1),
                identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
            )

    def test_session_token_too_short(self):
        """Test validation error when session token is too short."""
        with pytest.raises(ValidationError, match="at least 100 characters"):
            AWSCredentials(
                access_key_id="ASIAXAMPLEXAMPLEXA",
                secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
                session_token="short",
                expiration=datetime.now(UTC) + timedelta(hours=1),
                identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
            )

    def test_invalid_identity_id_format(self):
        """Test validation error for invalid identity ID format."""
        with pytest.raises(ValidationError):
            AWSCredentials(
                access_key_id="ASIAXAMPLEXAMPLEXA",
                secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
                session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
                expiration=datetime.now(UTC) + timedelta(hours=1),
                identity_id="invalid-format",
            )

    def test_valid_identity_id_formats(self):
        """Test various valid identity ID formats."""
        valid_ids = [
            "us-east-1:12345678-1234-1234-1234-123456789012",
            "eu-west-1:abcdefgh-1234-5678-90ab-cdefgh123456",
            "ap-northeast-1:00000000-0000-0000-0000-000000000000",
        ]

        for identity_id in valid_ids:
            credentials = AWSCredentials(
                access_key_id="ASIAXAMPLEXAMPLEXA",
                secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
                session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
                expiration=datetime.now(UTC) + timedelta(hours=1),
                identity_id=identity_id,
            )
            assert credentials.identity_id == identity_id

    def test_different_regions(self):
        """Test credentials with different AWS regions."""
        regions = [
            "us-east-1",
            "us-west-2",
            "eu-west-1",
            "eu-central-1",
            "ap-southeast-1",
            "ap-northeast-1",
        ]

        for region in regions:
            identity_id = f"{region}:12345678-1234-1234-1234-123456789012"
            credentials = AWSCredentials(
                access_key_id="ASIAXAMPLEXAMPLEXA",
                secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
                session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
                expiration=datetime.now(UTC) + timedelta(hours=1),
                identity_id=identity_id,
            )
            assert credentials.identity_id.startswith(region)

    def test_expiration_very_soon(self):
        """Test credentials expiring very soon."""
        expiration = datetime.now(UTC) + timedelta(seconds=30)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        time_left = credentials.time_until_expiration()
        assert time_left > 0
        assert time_left < 60  # Less than 1 minute

    def test_json_serialization(self):
        """Test that credentials can be serialized to JSON."""
        expiration = datetime(2026, 1, 29, 15, 0, 0, tzinfo=UTC)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        json_str = credentials.model_dump_json()
        assert "ASIAXAMPLEXAMPLEXA" in json_str
        assert "us-east-1:12345678-1234-1234-1234-123456789012" in json_str

    def test_maximum_duration_credentials(self):
        """Test credentials with maximum allowed duration (1 hour)."""
        expiration = datetime.now(UTC) + timedelta(hours=1)

        credentials = AWSCredentials(
            access_key_id="ASIAXAMPLEXAMPLEXA",
            secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
            session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
            expiration=expiration,
            identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
        )

        time_left = credentials.time_until_expiration()
        assert time_left <= 3600  # 1 hour

    def test_real_aws_access_key_format(self):
        """Test with realistic AWS access key format."""
        # Real AWS temporary access keys start with ASIA
        real_access_keys = [
            "ASIAXAMPLE123456",
            "ASIA1234567890AB",
            "ASIAZ9Y8X7W6V5U4",
        ]

        for access_key in real_access_keys:
            credentials = AWSCredentials(
                access_key_id=access_key,
                secret_access_key="secretaccesskeyexamplesecretaccesskeyexample",
                session_token="FwoGZXIvYXdzEBExample" + "x" * 100,
                expiration=datetime.now(UTC) + timedelta(hours=1),
                identity_id="us-east-1:12345678-1234-1234-1234-123456789012",
            )
            assert credentials.access_key_id.startswith("ASIA")
