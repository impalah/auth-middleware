from fastapi import HTTPException
from starlette.status import HTTP_401_UNAUTHORIZED


class AuthenticationError(HTTPException):
    """Raised when credentials are invalid or the session has expired."""

    def __init__(self, detail: str = "Invalid credentials") -> None:
        super().__init__(status_code=HTTP_401_UNAUTHORIZED, detail=detail)
