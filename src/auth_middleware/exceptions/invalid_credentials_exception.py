from fastapi import HTTPException


class InvalidCredentialsException(HTTPException):
    """Exception thrown when the user credentials are invalid

    Args:
        HTTPException (_type_): _description_
    """

    ...
