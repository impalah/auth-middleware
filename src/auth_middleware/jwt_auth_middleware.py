from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import HTTPException, Request, status
from fastapi.security.utils import get_authorization_scheme_param
from pydantic import ValidationError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from auth_middleware.contracts.jwt_provider import JWTProvider
from auth_middleware.exceptions.identity_provider_unavailable_exception import (
    IdentityProviderUnavailableException,
)
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.jwt_bearer_manager import JWTBearerManager
from auth_middleware.logging import logger
from auth_middleware.providers.oidc.oidc_exception import OidcException
from auth_middleware.settings import settings
from auth_middleware.types.jwt import JWTAuthorizationCredentials
from auth_middleware.types.user import User


@dataclass(frozen=True, slots=True)
class AuthFailure:
    """What an ``error_responder`` is told about a rejected request.

    ``reason`` is meant for logs and metrics; the exception text is never
    passed, and by default nothing of it reaches the response body.
    """

    status_code: int
    reason: Literal["invalid_token", "bad_scheme", "internal", "unavailable"]


class JwtAuthMiddleware(BaseHTTPMiddleware):
    """JWT Authorization middleware for FastAPI
    Adds the current user to the request state.

    Every option below is keyword-only and defaults to the historical behaviour.

    Args:
        app: The ASGI application.
        auth_provider: The JWT provider validating tokens.
        canonical_bearer_scheme: Treat the ``Authorization`` scheme case-insensitively
            (RFC 7235): ``bearer``/``BEARER`` are rewritten to ``Bearer`` before
            validation. Other schemes keep their own rejection status.
        path_prefix: Only requests whose path equals the prefix or starts with
            ``prefix + "/"`` are authenticated; others skip the middleware entirely
            and ``request.state.current_user`` is **not** set for them. Useful when
            other apps are mounted inside this one with their own middleware.
        error_responder: Builds the response for invalid token, bad scheme and
            internal errors from ``(request, AuthFailure)``. The default keeps the
            ``{"detail": ...}`` JSON bodies.
        strict: Raise ``RuntimeError`` at construction when
            ``AUTH_MIDDLEWARE_DISABLED`` is set or the provider's settings have
            ``jwt_token_verification_disabled=True``.
    """

    _auth_provider: JWTProvider
    _jwt_bearer_manager: JWTBearerManager

    def __init__(
        self,
        app: ASGIApp,
        auth_provider: JWTProvider,
        *args: Any,
        canonical_bearer_scheme: bool = False,
        path_prefix: str | None = None,
        error_responder: Callable[[Request, AuthFailure], Response] | None = None,
        strict: bool = False,
        **kwargs: Any,
    ) -> None:
        if strict:
            self._refuse_disabled_verification(auth_provider)
        if settings.AUTH_MIDDLEWARE_DISABLED:
            logger.warning(
                "AUTH_MIDDLEWARE_DISABLED is set: authentication and the legacy "
                "guards are OFF and every request is treated as the synthetic user. "
                "Never use this in production."
            )
        super().__init__(app, *args, **kwargs)
        self._canonical_bearer_scheme = canonical_bearer_scheme
        if path_prefix is not None and not path_prefix.startswith("/"):
            # "api" would never match: nothing would be authenticated (fail open).
            raise ValueError("path_prefix must start with '/'")
        self._path_prefix = path_prefix.rstrip("/") if path_prefix else None
        self._error_responder = error_responder
        self._auth_provider = auth_provider
        self._jwt_bearer_manager = JWTBearerManager(
            auth_provider=self._auth_provider,
        )

    @staticmethod
    def _refuse_disabled_verification(auth_provider: JWTProvider) -> None:
        provider_settings = getattr(auth_provider, "_settings", None)
        if settings.AUTH_MIDDLEWARE_DISABLED:
            raise RuntimeError(
                "strict mode: AUTH_MIDDLEWARE_DISABLED is set, refusing to start "
                "with authentication disabled"
            )
        if getattr(provider_settings, "jwt_token_verification_disabled", False):
            raise RuntimeError(
                "strict mode: jwt_token_verification_disabled is set on the provider, "
                "refusing to start with token verification disabled"
            )

    def _in_scope(self, request: Request) -> bool:
        if self._path_prefix is None:
            return True
        path: str = request.scope["path"]
        return path == self._path_prefix or path.startswith(self._path_prefix + "/")

    @staticmethod
    def _canonicalize_scheme(request: Request) -> None:
        """Rewrite a ``bearer``/``BEARER`` scheme to ``Bearer`` in the ASGI scope.

        Must run before anything reads ``request.headers`` (it caches).
        """
        headers: list[tuple[bytes, bytes]] = list(request.scope.get("headers", []))
        for i, (name, value) in enumerate(headers):
            if name.lower() != b"authorization":
                continue
            scheme, _, rest = value.partition(b" ")
            if scheme.lower() == b"bearer" and scheme != b"Bearer":
                headers[i] = (name, b"Bearer " + rest)
        request.scope["headers"] = headers

    def _failure(
        self,
        request: Request,
        failure: AuthFailure,
        detail: Any,
        headers: Mapping[str, str] | None = None,
    ) -> Response:
        """Custom responder if any, else the historical ``{"detail": ...}`` JSON."""
        if self._error_responder is not None:
            try:
                return self._error_responder(request, failure)
            except Exception:
                # A broken custom responder must not turn into an unhandled error.
                logger.opt(exception=True).error(
                    "error_responder failed; using default"
                )
        return JSONResponse(
            status_code=failure.status_code,
            content={"detail": detail},
            headers=headers,
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response | JSONResponse:
        if not self._in_scope(request):
            return await call_next(request)
        if self._canonical_bearer_scheme:
            self._canonicalize_scheme(request)
        try:
            request.state.current_user = await self.get_current_user(request=request)
        except IdentityProviderUnavailableException as ipe:
            # The identity provider is down: an outage (503), not a bad credential.
            logger.error("Identity provider unavailable: {}", str(ipe))
            return self._failure(
                request,
                AuthFailure(status.HTTP_503_SERVICE_UNAVAILABLE, "unavailable"),
                "Authentication service unavailable",
                {"Retry-After": "5"},
            )
        except (InvalidTokenException, ValidationError, OidcException) as ite:
            # A validly signed token the library cannot turn into a user (missing
            # sub, over-long claims, malformed e-mail) is a bad token, not a 500.
            logger.error("Invalid Token {}", str(ite))
            return self._failure(
                request,
                AuthFailure(status.HTTP_401_UNAUTHORIZED, "invalid_token"),
                "Invalid token",
                {"WWW-Authenticate": "Bearer"},
            )
        except HTTPException as http_exc:
            # e.g. an Authorization scheme other than Bearer, rejected by
            # HTTPBearer. It is a client error: answer with its own status,
            # not a 500.
            logger.error("Authentication rejected: {}", str(http_exc))
            return self._failure(
                request,
                AuthFailure(http_exc.status_code, "bad_scheme"),
                http_exc.detail,
                http_exc.headers,
            )
        except Exception as e:
            # Log the cause; never send it to the client (it can reveal internals).
            logger.error("Error in AuthMiddleware: {}", str(e))
            return self._failure(
                request,
                AuthFailure(status.HTTP_500_INTERNAL_SERVER_ERROR, "internal"),
                "Internal server error",
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
            if settings.AUTH_MIDDLEWARE_DISABLED:
                return User.synthetic()

            if not self.__validate_credentials(request=request):
                logger.debug("There are no credentials in the request")
                return None

            token: (
                JWTAuthorizationCredentials | None
            ) = await self._jwt_bearer_manager.get_credentials(request=request)

            # Create User object from token
            if token is None:  # pragma: no cover - guarded by __validate_credentials
                raise InvalidTokenException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="No token"
                )
            user: User = await self._auth_provider.create_user_from_token(token=token)
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
