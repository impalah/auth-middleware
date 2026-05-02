"""Unit tests for CognitoAuthService — all Cognito client calls are mocked."""

from unittest.mock import MagicMock

import pytest

from auth_middleware.exceptions.authentication_error import AuthenticationError
from auth_middleware.exceptions.password_policy_error import PasswordPolicyError
from auth_middleware.exceptions.user_not_found_error import UserNotFoundError
from auth_middleware.providers.aws.cognito_exceptions import (
    InvalidChallengeError,
    MfaSetupError,
)
from auth_middleware.providers.aws.services.cognito_auth_models import TokenResponse
from auth_middleware.providers.aws.services.cognito_auth_service import (
    CognitoAuthService,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeClientError(Exception):
    """Minimal stand-in for botocore.exceptions.ClientError."""

    def __init__(self, code: str) -> None:
        self.response = {"Error": {"Code": code, "Message": code}}
        super().__init__(code)


def _client_error(code: str) -> _FakeClientError:
    return _FakeClientError(code)


def _auth_result() -> dict:
    return {
        "AuthenticationResult": {
            "AccessToken": "access-token",
            "IdToken": "id-token",
            "RefreshToken": "refresh-token",
            "ExpiresIn": 3600,
        }
    }


def _make_service(*, with_secret: bool = False) -> CognitoAuthService:
    """Create a CognitoAuthService with an injected mock cognito client."""
    return CognitoAuthService(
        client_id="test-client-id",
        user_pool_id="eu-west-1_TESTPOOL",
        region="eu-west-1",
        client_secret="test-secret" if with_secret else None,
        cognito_client=MagicMock(),
    )


@pytest.fixture
def svc() -> CognitoAuthService:
    return _make_service()


@pytest.fixture
def svc_with_secret() -> CognitoAuthService:
    return _make_service(with_secret=True)


# ---------------------------------------------------------------------------
# _secret_hash
# ---------------------------------------------------------------------------


def test_secret_hash_returns_none_without_secret(svc):
    assert svc._secret_hash("user@example.com") is None


def test_secret_hash_returns_string_with_secret(svc_with_secret):
    result = svc_with_secret._secret_hash("user@example.com")
    assert isinstance(result, str)
    assert len(result) > 0


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


def test_login_success_returns_tokens(svc):
    svc._cognito.initiate_auth.return_value = _auth_result()

    result = svc.login("user@example.com", "password")

    assert result.tokens is not None
    assert result.tokens.access_token == "access-token"
    assert result.tokens.id_token == "id-token"
    assert result.tokens.refresh_token == "refresh-token"
    assert result.challenge is None


def test_login_returns_mfa_challenge(svc):
    svc._cognito.initiate_auth.return_value = {
        "ChallengeName": "SOFTWARE_TOKEN_MFA",
        "Session": "session-token",
    }

    result = svc.login("user@example.com", "password")

    assert result.tokens is None
    assert result.challenge is not None
    assert result.challenge.challenge == "MFA_TOTP"
    assert result.challenge.session == "session-token"


def test_login_returns_new_password_challenge(svc):
    svc._cognito.initiate_auth.return_value = {
        "ChallengeName": "NEW_PASSWORD_REQUIRED",
        "Session": "session-xyz",
    }

    result = svc.login("user@example.com", "password")

    assert result.challenge.challenge == "NEW_PASSWORD_REQUIRED"


def test_login_raises_authentication_error_on_not_authorized(svc):
    svc._cognito.initiate_auth.side_effect = _client_error("NotAuthorizedException")

    with pytest.raises(AuthenticationError):
        svc.login("user@example.com", "wrong-password")


def test_login_raises_authentication_error_on_user_not_found(svc):
    svc._cognito.initiate_auth.side_effect = _client_error("UserNotFoundException")

    with pytest.raises(AuthenticationError):
        svc.login("unknown@example.com", "password")


def test_login_raises_authentication_error_on_password_reset_required(svc):
    svc._cognito.initiate_auth.side_effect = _client_error(
        "PasswordResetRequiredException"
    )

    with pytest.raises(AuthenticationError) as exc_info:
        svc.login("user@example.com", "password")
    assert "reset" in str(exc_info.value.detail).lower()


def test_login_reraises_unknown_client_error(svc):
    svc._cognito.initiate_auth.side_effect = _client_error("InternalErrorException")

    with pytest.raises(_FakeClientError):
        svc.login("user@example.com", "password")


# ---------------------------------------------------------------------------
# respond_to_challenge
# ---------------------------------------------------------------------------


def test_respond_to_challenge_totp_success(svc):
    svc._cognito.respond_to_auth_challenge.return_value = _auth_result()

    result = svc.respond_to_challenge(
        session="session-token",
        challenge="MFA_TOTP",
        response="123456",
        username="user@example.com",
    )

    assert result.tokens is not None
    assert result.tokens.access_token == "access-token"
    call_kwargs = svc._cognito.respond_to_auth_challenge.call_args[1]
    assert call_kwargs["ChallengeName"] == "SOFTWARE_TOKEN_MFA"
    assert call_kwargs["ChallengeResponses"]["SOFTWARE_TOKEN_MFA_CODE"] == "123456"


def test_respond_to_challenge_sms_success(svc):
    svc._cognito.respond_to_auth_challenge.return_value = _auth_result()

    result = svc.respond_to_challenge(
        session="session-token",
        challenge="SMS_MFA",
        response="654321",
    )

    assert result.tokens is not None
    call_kwargs = svc._cognito.respond_to_auth_challenge.call_args[1]
    assert call_kwargs["ChallengeResponses"]["SMS_MFA_CODE"] == "654321"


def test_respond_to_challenge_new_password_success(svc):
    svc._cognito.respond_to_auth_challenge.return_value = _auth_result()

    result = svc.respond_to_challenge(
        session="session",
        challenge="NEW_PASSWORD_REQUIRED",
        response="NewPass123!",
        username="user@example.com",
    )

    assert result.tokens is not None
    call_kwargs = svc._cognito.respond_to_auth_challenge.call_args[1]
    assert call_kwargs["ChallengeResponses"]["NEW_PASSWORD"] == "NewPass123!"


def test_respond_to_challenge_raises_invalid_on_code_mismatch(svc):
    svc._cognito.respond_to_auth_challenge.side_effect = _client_error(
        "CodeMismatchException"
    )

    with pytest.raises(InvalidChallengeError):
        svc.respond_to_challenge("s", "MFA_TOTP", "000000")


def test_respond_to_challenge_raises_password_policy_error(svc):
    svc._cognito.respond_to_auth_challenge.side_effect = _client_error(
        "InvalidPasswordException"
    )

    with pytest.raises(PasswordPolicyError):
        svc.respond_to_challenge("s", "NEW_PASSWORD_REQUIRED", "weak")


def test_respond_to_challenge_returns_nested_challenge(svc):
    svc._cognito.respond_to_auth_challenge.return_value = {
        "ChallengeName": "NEW_PASSWORD_REQUIRED",
        "Session": "new-session",
    }

    result = svc.respond_to_challenge("s", "MFA_TOTP", "123456")

    assert result.challenge is not None
    assert result.challenge.challenge == "NEW_PASSWORD_REQUIRED"


# ---------------------------------------------------------------------------
# logout
# ---------------------------------------------------------------------------


def test_logout_success(svc):
    svc._cognito.global_sign_out.return_value = {}

    result = svc.logout("access-token")

    assert result.message == "Logged out successfully"
    svc._cognito.global_sign_out.assert_called_once_with(AccessToken="access-token")


def test_logout_raises_authentication_error_on_invalid_token(svc):
    svc._cognito.global_sign_out.side_effect = _client_error("NotAuthorizedException")

    with pytest.raises(AuthenticationError):
        svc.logout("expired-token")


# ---------------------------------------------------------------------------
# refresh
# ---------------------------------------------------------------------------


def test_refresh_success(svc):
    svc._cognito.initiate_auth.return_value = _auth_result()

    result = svc.refresh("my-refresh-token")

    assert isinstance(result, TokenResponse)
    assert result.access_token == "access-token"
    call_kwargs = svc._cognito.initiate_auth.call_args[1]
    assert call_kwargs["AuthFlow"] == "REFRESH_TOKEN_AUTH"
    assert call_kwargs["AuthParameters"]["REFRESH_TOKEN"] == "my-refresh-token"


def test_refresh_raises_authentication_error_on_expired_token(svc):
    svc._cognito.initiate_auth.side_effect = _client_error("NotAuthorizedException")

    with pytest.raises(AuthenticationError):
        svc.refresh("expired-refresh-token")


# ---------------------------------------------------------------------------
# get_user
# ---------------------------------------------------------------------------


def test_get_user_returns_me_response(svc):
    svc._cognito.get_user.return_value = {
        "Username": "user@example.com",
        "UserAttributes": [
            {"Name": "sub", "Value": "uuid-123"},
            {"Name": "email", "Value": "user@example.com"},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "name", "Value": "John Doe"},
        ],
    }
    svc._cognito.admin_list_groups_for_user.return_value = {
        "Groups": [{"GroupName": "teachers"}, {"GroupName": "admins"}]
    }

    result = svc.get_user("access-token")

    assert result.sub == "uuid-123"
    assert result.email == "user@example.com"
    assert result.email_verified is True
    assert result.name == "John Doe"
    assert "teachers" in result.groups
    assert "admins" in result.groups


def test_get_user_returns_empty_groups_on_group_error(svc):
    svc._cognito.get_user.return_value = {
        "Username": "user@example.com",
        "UserAttributes": [{"Name": "sub", "Value": "uuid-123"}],
    }
    svc._cognito.admin_list_groups_for_user.side_effect = _client_error(
        "AccessDeniedException"
    )

    result = svc.get_user("access-token")

    assert result.groups == []


def test_get_user_raises_authentication_error_on_invalid_token(svc):
    svc._cognito.get_user.side_effect = _client_error("NotAuthorizedException")

    with pytest.raises(AuthenticationError):
        svc.get_user("invalid-token")


# ---------------------------------------------------------------------------
# change_password
# ---------------------------------------------------------------------------


def test_change_password_success(svc):
    svc._cognito.change_password.return_value = {}

    result = svc.change_password("access-token", "OldPass1!", "NewPass2!")

    assert result.message == "Password changed successfully"
    svc._cognito.change_password.assert_called_once_with(
        AccessToken="access-token",
        PreviousPassword="OldPass1!",
        ProposedPassword="NewPass2!",
    )


def test_change_password_raises_authentication_error_on_wrong_current(svc):
    svc._cognito.change_password.side_effect = _client_error("NotAuthorizedException")

    with pytest.raises(AuthenticationError):
        svc.change_password("token", "wrong-old", "NewPass2!")


def test_change_password_raises_policy_error(svc):
    svc._cognito.change_password.side_effect = _client_error("InvalidPasswordException")

    with pytest.raises(PasswordPolicyError):
        svc.change_password("token", "OldPass1!", "weak")


# ---------------------------------------------------------------------------
# forgot_password
# ---------------------------------------------------------------------------


def test_forgot_password_success(svc):
    svc._cognito.forgot_password.return_value = {
        "CodeDeliveryDetails": {
            "DeliveryMedium": "EMAIL",
            "Destination": "u***@example.com",
        }
    }

    result = svc.forgot_password("user@example.com")

    assert result.delivery_medium == "EMAIL"
    assert result.destination == "u***@example.com"


def test_forgot_password_raises_user_not_found(svc):
    svc._cognito.forgot_password.side_effect = _client_error("UserNotFoundException")

    with pytest.raises(UserNotFoundError):
        svc.forgot_password("unknown@example.com")


# ---------------------------------------------------------------------------
# reset_password
# ---------------------------------------------------------------------------


def test_reset_password_success(svc):
    svc._cognito.confirm_forgot_password.return_value = {}

    result = svc.reset_password("user@example.com", "123456", "NewPass1!")

    assert result.message == "Password reset successfully"


def test_reset_password_raises_invalid_on_code_mismatch(svc):
    svc._cognito.confirm_forgot_password.side_effect = _client_error(
        "CodeMismatchException"
    )

    with pytest.raises(InvalidChallengeError):
        svc.reset_password("user@example.com", "999999", "NewPass1!")


def test_reset_password_raises_invalid_on_expired_code(svc):
    svc._cognito.confirm_forgot_password.side_effect = _client_error(
        "ExpiredCodeException"
    )

    with pytest.raises(InvalidChallengeError):
        svc.reset_password("user@example.com", "000000", "NewPass1!")


def test_reset_password_raises_policy_error(svc):
    svc._cognito.confirm_forgot_password.side_effect = _client_error(
        "InvalidPasswordException"
    )

    with pytest.raises(PasswordPolicyError):
        svc.reset_password("user@example.com", "123456", "weak")


def test_reset_password_raises_user_not_found(svc):
    svc._cognito.confirm_forgot_password.side_effect = _client_error(
        "UserNotFoundException"
    )

    with pytest.raises(UserNotFoundError):
        svc.reset_password("unknown@example.com", "123456", "NewPass1!")


# ---------------------------------------------------------------------------
# setup_totp
# ---------------------------------------------------------------------------


def test_setup_totp_returns_secret_and_qr(svc):
    svc._cognito.associate_software_token.return_value = {
        "SecretCode": "JBSWY3DPEHPK3PXP"
    }

    result = svc.setup_totp("access-token")

    assert result.secret_code == "JBSWY3DPEHPK3PXP"
    assert "otpauth://totp/" in result.qr_uri
    assert "JBSWY3DPEHPK3PXP" in result.qr_uri


def test_setup_totp_raises_mfa_setup_error_on_failure(svc):
    svc._cognito.associate_software_token.side_effect = _client_error(
        "InvalidParameterException"
    )

    with pytest.raises(MfaSetupError):
        svc.setup_totp("access-token")


# ---------------------------------------------------------------------------
# verify_totp
# ---------------------------------------------------------------------------


def test_verify_totp_success(svc):
    svc._cognito.verify_software_token.return_value = {}
    svc._cognito.set_user_mfa_preference.return_value = {}

    result = svc.verify_totp("access-token", "123456", "My Phone")

    assert result.message == "TOTP MFA enabled successfully"
    svc._cognito.set_user_mfa_preference.assert_called_once_with(
        AccessToken="access-token",
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )


def test_verify_totp_raises_mfa_setup_error_on_code_mismatch(svc):
    svc._cognito.verify_software_token.side_effect = _client_error(
        "CodeMismatchException"
    )

    with pytest.raises(MfaSetupError):
        svc.verify_totp("access-token", "000000", "My Phone")


# ---------------------------------------------------------------------------
# disable_totp
# ---------------------------------------------------------------------------


def test_disable_totp_success(svc):
    svc._cognito.set_user_mfa_preference.return_value = {}

    result = svc.disable_totp("access-token")

    assert result.message == "TOTP MFA disabled"
    svc._cognito.set_user_mfa_preference.assert_called_once_with(
        AccessToken="access-token",
        SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
    )


def test_disable_totp_raises_mfa_setup_error_on_failure(svc):
    svc._cognito.set_user_mfa_preference.side_effect = _client_error(
        "NotAuthorizedException"
    )

    with pytest.raises(MfaSetupError):
        svc.disable_totp("access-token")
