"""Auth-middleware exceptions."""

from auth_middleware.exceptions.cognito_exceptions import (
    AuthenticationError,
    ChallengeRequiredError,
    InvalidChallengeError,
    MfaSetupError,
    PasswordPolicyError,
    UserNotFoundError,
)
from auth_middleware.exceptions.invalid_authorization_exception import InvalidAuthorizationException
from auth_middleware.exceptions.invalid_credentials_exception import InvalidCredentialsException
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException

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
