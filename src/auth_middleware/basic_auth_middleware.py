import base64
from typing import List, Optional, Tuple

from fastapi import Request, status
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from auth_middleware.exceptions import InvalidTokenException
from auth_middleware.jwt_auth_provider import JWTAuthProvider
from auth_middleware.jwt_bearer_manager import JWTBearerManager
from auth_middleware.logging import logger
from auth_middleware.settings import settings
from auth_middleware.types import JWTAuthorizationCredentials, User


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Basic scheme Authorization middleware for FastAPI
    Adds the current user to the request state.

    Args:
        BaseHTTPMiddleware (_type_): _description_
    """

    _auth_provider: JWTAuthProvider

    def __init__(self, auth_provider: JWTAuthProvider, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_provider = auth_provider

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response | JSONResponse:
        try:
            request.state.current_user = await self.get_current_user(request=request)
        except InvalidTokenException as ite:
            logger.error("Invalid Token {}", str(ite))
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid token"},
                headers={"WWW-Authenticate": "Bearer"},
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
            raise InvalidTokenException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid authorization header",
            )

        if not credentials:
            return None

        # Check scheme
        # TODO: use a constant for the string "basic"
        if not credentials[0] or credentials[0].lower() != "basic":
            logger.error("Error in get_credentials: Wrong authentication method")
            raise InvalidTokenException(
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
            raise InvalidTokenException(
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

        try:

            if not self.__validate_credentials(request=request):
                logger.debug("There are no credentials in the request")
                return None

            credentials: Tuple[str, str] = await self.get_credentials(request=request)
            logger.debug("Credentials: {}", credentials)

            # Validate credentials
            # First test
            if credentials[0] != "demouser":
                logger.error("Invalid User and/or Password")
                raise InvalidTokenException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Invalid User credentials",
                )

            # Create User object from token
            user: User = (
                self.create_user_from_credentials(credentials=credentials)
                if credentials
                else self.__create_synthetic_user()
            )
            logger.debug("Returning {}", user)
            return user
        except InvalidTokenException as ite:
            logger.error("Invalid Token {}", str(ite))
            raise
        except Exception as e:
            logger.error("Not controlled exception {}", str(e))
            raise

    def __validate_credentials(self, request: Request) -> bool:
        """Validate if credentials exist in the request headers

        Args:
            request (Request): _description_

        Returns:
            bool: _description_
        """
        authorization = request.headers.get("Authorization")
        scheme, credentials = get_authorization_scheme_param(authorization)
        return bool(authorization and scheme and credentials)

    def __create_synthetic_user(self) -> User:
        """Create a synthetic user for testing purposes

        Returns:
            User: Domain object.
        """
        return User(
            id="synthetic",
            name="synthetic",
            groups=[],
            email="synthetic@email.com",
        )

    def create_user_from_credentials(self, credentials: Tuple[str, str]) -> User:
        """Create a User object from credentials

        Args:
            credentials (Tuple[str, str]): _description_

        Returns:
            User: _description_
        """

        groups: List[str] = []

        # groups: List[str] = (
        #     self.__get_groups_from_claims(token.claims)
        #     if "cognito:groups" in token.claims or "scope" in token.claims
        #     else []
        # )

        return User(
            id=credentials[0],
            name=credentials[0],
            groups=groups,
            email=None,
        )
