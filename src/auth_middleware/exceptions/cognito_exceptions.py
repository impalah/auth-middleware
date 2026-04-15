"""Cognito-specific domain exceptions for authentication and MFA operations."""

from fastapi import HTTPException
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
)


class AuthenticationError(HTTPException):
    """Raised when credentials are invalid or the session has expired."""

    def __init__(self, detail: str = "Invalid credentials") -> None:
        super().__init__(status_code=HTTP_401_UNAUTHORIZED, detail=detail)


class ChallengeRequiredError(Exception):
    """Internal signal: Cognito returned a challenge instead of tokens.

    Not raised directly to the HTTP layer — caught by the service and
    converted to a ChallengeResponse.
    """

    def __init__(self, challenge_name: str, session: str) -> None:
        self.challenge_name = challenge_name
        self.session = session


class InvalidChallengeError(HTTPException):
    """Raised when the challenge response is incorrect or the session is expired."""

    def __init__(self, detail: str = "Invalid or expired challenge") -> None:
        super().__init__(status_code=HTTP_400_BAD_REQUEST, detail=detail)


class PasswordPolicyError(HTTPException):
    """Raised when the new password does not meet Cognito's password policy."""

    def __init__(self, detail: str = "Password does not meet policy requirements") -> None:
        super().__init__(status_code=HTTP_400_BAD_REQUEST, detail=detail)


class UserNotFoundError(HTTPException):
    """Raised when the requested user does not exist in the user pool."""

    def __init__(self, detail: str = "User not found") -> None:
        super().__init__(status_code=HTTP_404_NOT_FOUND, detail=detail)


class MfaSetupError(HTTPException):
    """Raised when a TOTP setup or verification operation fails."""

    def __init__(self, detail: str = "MFA setup failed") -> None:
        super().__init__(status_code=HTTP_400_BAD_REQUEST, detail=detail)
