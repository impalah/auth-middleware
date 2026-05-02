from fastapi import HTTPException
from starlette.status import HTTP_400_BAD_REQUEST


class PasswordPolicyError(HTTPException):
    """Raised when the new password does not meet the password policy."""

    def __init__(
        self, detail: str = "Password does not meet policy requirements"
    ) -> None:
        super().__init__(status_code=HTTP_400_BAD_REQUEST, detail=detail)
