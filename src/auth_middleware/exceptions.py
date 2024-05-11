from fastapi import HTTPException


class InvalidTokenException(HTTPException):
    """Exception thrown when the token is invalid

    Args:
        HTTPException (_type_): _description_
    """

    ...


class InvalidCredentialsException(HTTPException):
    """Exception thrown when the user credentials are invalid

    Args:
        HTTPException (_type_): _description_
    """

    ...


class InvalidAuthorizationException(HTTPException):
    """Exception thrown when the authorization header is invalid

    Args:
        HTTPException (_type_): _description_
    """

    ...
