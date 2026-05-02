"""Cognito-specific exceptions for challenge and MFA flows."""

from fastapi import HTTPException
from starlette.status import HTTP_400_BAD_REQUEST


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


class MfaSetupError(HTTPException):
    """Raised when a TOTP setup or verification operation fails."""

    def __init__(self, detail: str = "MFA setup failed") -> None:
        super().__init__(status_code=HTTP_400_BAD_REQUEST, detail=detail)
