from fastapi import HTTPException


class InvalidTokenException(HTTPException):
    pass
