import base64
import hashlib
from typing import List, Optional, Tuple

from fastapi import Request, status
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from auth_middleware.auth_provider import AuthProvider
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.exceptions.invalid_authorization_exception import (
    InvalidAuthorizationException,
)
from auth_middleware.exceptions.invalid_credentials_exception import (
    InvalidCredentialsException,
)

from auth_middleware.jwt_bearer_manager import JWTBearerManager
from auth_middleware.logging import logger
from auth_middleware.repository.credentials_repository import CredentialsRepository
from auth_middleware.settings import settings
from auth_middleware.types.user import User
from auth_middleware.types.user_credentials import UserCredentials


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Basic scheme Authorization middleware for FastAPI
    Adds the current user to the request state.

    Args:
        BaseHTTPMiddleware (_type_): _description_
    """

    _credentials_repository: CredentialsRepository

    def __init__(self, credentials_repository: CredentialsRepository, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._credentials_repository = credentials_repository

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response | JSONResponse:
        try:
            request.state.current_user = await self.get_current_user(request=request)
        except InvalidAuthorizationException as ite:
            logger.error("Invalid authorization {}", str(ite))
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid authorization header"},
                headers={"WWW-Authenticate": "Basic realm=Restricted Access"},
            )
        except Exception as e:
            logger.error("Error in AuthMiddleware: {}", str(e))
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": f"Server error: {str(e)}"},
            )

        response = await call_next(request)
        return response

    async def get_credentials(self, request: Request) -> Tuple[str, str] | None:
        """Get credentials from the request

        Args:
            request (Request): _description_

        Raises:
            InvalidTokenException: _description_

        Returns:
            Tuple[str, str] | None: _description_
        """

        if settings.AUTH_MIDDLEWARE_DISABLED:
            return None

        credentials: Tuple[str, str] | None = None

        # Try to decode the base64 encoded credentials
        try:
            authorization = request.headers.get("Authorization")
            credentials = get_authorization_scheme_param(authorization)
        except Exception as e:
            logger.error("Error in get_credentials: {}", str(e))
            raise InvalidAuthorizationException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authorization header",
            )

        if not credentials:
            logger.error("Error in get_credentials: No credentials in the request")
            return None

        # Check scheme
        # TODO: use a constant for the string "basic"
        if not credentials[0] or credentials[0].lower() != "basic":
            logger.error("Error in get_credentials: Wrong authentication method")
            raise InvalidAuthorizationException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Wrong authentication method",
            )

        try:
            # Decode the base64 encoded credentials
            decoded_credentials = base64.b64decode(credentials[1]).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)
            return username, password

        except Exception as e:
            logger.error("Error in JWTBearerManager: {}", str(e))
            raise InvalidCredentialsException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authentication credentials",
            )

    async def get_current_user(self, request: Request) -> User | None:
        """Get current logged in and active user


        Raises:
            HTTPException: _description_

        Returns:
            User: Domain object.
        """

        logger.debug("Get Current Active User ...")

        # Recover credentials from the request
        credentials: Tuple[str, str] = await self.get_credentials(request=request)
        logger.debug("Credentials: {}", credentials)

        # Get user credentials from the repository
        user_credentials: UserCredentials = (
            await self._credentials_repository.get_by_id(id=credentials[0])
        )

        if not user_credentials:
            logger.error("User not found")
            raise InvalidAuthorizationException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid User credentials",
            )

        # Validate credentials
        if (
            hashlib.sha256(credentials[1].encode()).hexdigest()
            != user_credentials.hashed_password
        ):
            raise InvalidAuthorizationException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid User credentials",
            )

        user: User = User(
            id=user_credentials.id,
            name=user_credentials.name,
            groups=user_credentials.groups,
            email=user_credentials.email,
        )

        # Return user
        logger.debug("Returning {}", user)
        return user
