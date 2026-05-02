"""Auth-middleware exceptions."""

from auth_middleware.exceptions.authentication_error import AuthenticationError
from auth_middleware.exceptions.invalid_authorization_exception import (
    InvalidAuthorizationException,
)
from auth_middleware.exceptions.invalid_credentials_exception import (
    InvalidCredentialsException,
)
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.exceptions.password_policy_error import PasswordPolicyError
from auth_middleware.exceptions.user_not_found_error import UserNotFoundError
from auth_middleware.providers.aws.cognito_exceptions import (
    ChallengeRequiredError,
    InvalidChallengeError,
    MfaSetupError,
)

__all__ = [
    "AuthenticationError",
    "ChallengeRequiredError",
    "InvalidChallengeError",
    "MfaSetupError",
    "PasswordPolicyError",
    "UserNotFoundError",
    "InvalidAuthorizationException",
    "InvalidCredentialsException",
    "InvalidTokenException",
]
