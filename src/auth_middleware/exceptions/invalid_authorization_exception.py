from fastapi import HTTPException


class InvalidAuthorizationException(HTTPException):
    """Exception thrown when the authorization header is invalid

    Args:
        HTTPException (_type_): _description_
    """

    ...
