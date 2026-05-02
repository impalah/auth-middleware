from fastapi import HTTPException
from starlette.status import HTTP_404_NOT_FOUND


class UserNotFoundError(HTTPException):
    """Raised when the requested user does not exist."""

    def __init__(self, detail: str = "User not found") -> None:
        super().__init__(status_code=HTTP_404_NOT_FOUND, detail=detail)
