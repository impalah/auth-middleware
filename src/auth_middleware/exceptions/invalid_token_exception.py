from fastapi import HTTPException


class InvalidTokenException(HTTPException):
    """Exception thrown when the token is invalid

    Args:
        HTTPException (_type_): _description_
    """

    ...
