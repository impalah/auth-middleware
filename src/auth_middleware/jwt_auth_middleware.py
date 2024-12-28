from typing import Optional

from fastapi import Request, status
from fastapi.security.utils import get_authorization_scheme_param
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.exceptions.invalid_authorization_exception import (
    InvalidAuthorizationException,
)
from auth_middleware.exceptions.invalid_credentials_exception import (
    InvalidCredentialsException,
)
from auth_middleware.types.jwt import JWTAuthorizationCredentials
from auth_middleware.providers.authn.jwt_provider import JWTProvider
from auth_middleware.jwt_bearer_manager import JWTBearerManager
from auth_middleware.logging import logger
from auth_middleware.types.user import User


class JwtAuthMiddleware(BaseHTTPMiddleware):
    """JWT Authorization middleware for FastAPI
    Adds the current user to the request state.

    Args:
        BaseHTTPMiddleware (_type_): _description_
    """

    _auth_provider: JWTProvider
    _jwt_bearer_manager = JWTBearerManager

    def __init__(
        self,
        auth_provider: JWTProvider,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._auth_provider = auth_provider
        self._jwt_bearer_manager = JWTBearerManager(
            auth_provider=self._auth_provider,
        )

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

            token: Optional[JWTAuthorizationCredentials] = (
                await self._jwt_bearer_manager.get_credentials(request=request)
            )

            # Create User object from token
            user: User = (
                await self._auth_provider.create_user_from_token(token=token)
                if token
                else self.__create_synthetic_user()
            )
            logger.debug("Returning {}", user)
            return user
        except InvalidTokenException as ite:
            logger.error("Invalid Token {}", str(ite))
            raise
        except Exception as e:
            # TODO: Control "No public key found that matches the one present in the TOKEN!"
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
