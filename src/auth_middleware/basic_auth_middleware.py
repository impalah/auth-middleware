import asyncio
import base64
from typing import Any

from fastapi import Request, status
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from auth_middleware.constants import AUTH_SCHEME_BASIC
from auth_middleware.contracts.credentials_repository import CredentialsRepository
from auth_middleware.exceptions.invalid_authorization_exception import (
    InvalidAuthorizationException,
)
from auth_middleware.exceptions.invalid_credentials_exception import (
    InvalidCredentialsException,
)
from auth_middleware.logging import logger
from auth_middleware.password_hasher import verify_password
from auth_middleware.settings import settings
from auth_middleware.types.user import User
from auth_middleware.types.user_credentials import UserCredentials

#: A valid but never-matching hash, verified for unknown users so that they cost the
#: same as a wrong password (no username enumeration through timing).
_DUMMY_HASH = (
    "pbkdf2_sha256$600000$e9755e6169c4dca5d3e791b040ee596e$"
    "63e49e1522933101511f9fefc3ae8fc385cc53ee023cc85c74d896855e789b3f"
)


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Basic scheme Authorization middleware for FastAPI
    Adds the current user to the request state.

    Args:
        BaseHTTPMiddleware (_type_): _description_
    """

    _credentials_repository: CredentialsRepository

    def __init__(
        self,
        app: ASGIApp,
        credentials_repository: CredentialsRepository,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        # `app` comes first because Starlette's `add_middleware` instantiates
        # `cls(app, **options)`.
        if settings.AUTH_MIDDLEWARE_DISABLED:
            logger.warning(
                "AUTH_MIDDLEWARE_DISABLED is set: authentication and the legacy "
                "guards are OFF and every request is treated as the synthetic user. "
                "Never use this in production."
            )
        super().__init__(app, *args, **kwargs)
        self._credentials_repository = credentials_repository

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response | JSONResponse:
        try:
            request.state.current_user = await self.get_current_user(request=request)
        except (InvalidAuthorizationException, InvalidCredentialsException) as ite:
            # A malformed header is a client error (401), never a 500.
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
                content={"detail": "Internal server error"},
            )

        response = await call_next(request)
        return response

    def get_credentials(self, request: Request) -> tuple[str, str] | None:
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

        credentials: tuple[str, str] | None = None

        # Try to decode the base64 encoded credentials
        try:
            authorization = request.headers.get("Authorization")
            credentials = get_authorization_scheme_param(authorization)
        except Exception as e:
            logger.error("Error in get_credentials: {}", str(e))
            raise InvalidAuthorizationException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authorization header",
            ) from e

        if not credentials:
            logger.error("Error in get_credentials: No credentials in the request")
            return None

        # Check scheme
        if not credentials[0] or credentials[0].lower() != AUTH_SCHEME_BASIC:
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
            ) from e

    async def get_current_user(self, request: Request) -> User | None:
        """Get current logged in and active user


        Raises:
            HTTPException: _description_

        Returns:
            User: Domain object.
        """

        logger.debug("Get Current Active User ...")

        if settings.AUTH_MIDDLEWARE_DISABLED:
            return User.synthetic()

        # Recover credentials from the request
        credentials: tuple[str, str] | None = self.get_credentials(request=request)
        if not credentials:
            raise InvalidAuthorizationException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No credentials provided",
            )

        # Get user credentials from the repository
        user_credentials: (
            UserCredentials | None
        ) = await self._credentials_repository.get_by_id(id=credentials[0])
        # Unknown user and wrong password must look the same, in status and in
        # time: always run the (deliberately slow) hash verification, and do it in
        # a worker thread so it does not block the event loop.
        stored_hash = (
            user_credentials.hashed_password if user_credentials else _DUMMY_HASH
        )
        password_ok = await asyncio.to_thread(
            verify_password, credentials[1], stored_hash
        )
        if not user_credentials or not password_ok:
            logger.error("Basic authentication failed")
            raise InvalidAuthorizationException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        user: User = User(
            id=user_credentials.id,
            name=user_credentials.name,
            groups=await user_credentials.groups,
            email=user_credentials.email,
        )

        # Return user
        logger.debug("Returning {}", user)
        return user
