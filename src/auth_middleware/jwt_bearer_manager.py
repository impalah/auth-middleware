import base64
import json
from typing import Any

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from joserfc.errors import JoseError
from starlette.requests import Request
from starlette.status import HTTP_403_FORBIDDEN

from auth_middleware.constants import AUTH_SCHEME_BEARER
from auth_middleware.contracts.jwt_provider import JWTProvider
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException
from auth_middleware.logging import logger
from auth_middleware.settings import settings
from auth_middleware.types.jwt import JWTAuthorizationCredentials


class JWTBearerManager(HTTPBearer):
    def __init__(
        self,
        auth_provider: JWTProvider,
        auto_error: bool = True,
    ):
        super().__init__(auto_error=auto_error)
        self.auth_provider = auth_provider

    async def get_credentials(
        self, request: Request
    ) -> JWTAuthorizationCredentials | None:
        if settings.AUTH_MIDDLEWARE_DISABLED:
            return None

        try:
            credentials: HTTPAuthorizationCredentials | None = await super().__call__(
                request
            )
        except HTTPException as e:
            logger.error("Error in JWTBearerManager: {}", str(e))
            raise e
        except Exception as e:
            logger.error("Error in JWTBearerManager: {}", str(e))
            raise InvalidTokenException(
                status_code=HTTP_403_FORBIDDEN,
                detail="JWK-invalid",
            ) from e

        if credentials:
            if credentials.scheme != AUTH_SCHEME_BEARER:
                logger.error("Error in JWTBearerManager: Wrong authentication method")
                raise InvalidTokenException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="Wrong authentication method",
                )

            jwt_token = credentials.credentials

            try:
                message, signature = jwt_token.rsplit(".", 1)
                _parts = jwt_token.split(".")

                def _b64d(part: str) -> dict[str, Any]:
                    padded = part + "=" * (-len(part) % 4)
                    return dict(json.loads(base64.urlsafe_b64decode(padded)))

                jwt_credentials = JWTAuthorizationCredentials(
                    jwt_token=jwt_token,
                    header=_b64d(_parts[0]),
                    claims=_b64d(_parts[1]),
                    signature=signature,
                    message=message,
                )

            except (JoseError, Exception) as jwt_err:
                logger.error("Error in JWTBearerManager: JWTError")
                raise InvalidTokenException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="JWK-invalid",
                ) from jwt_err

            if not await self.auth_provider.verify_token(jwt_credentials):
                logger.error("Error in JWTBearerManager: token not verified")
                raise InvalidTokenException(
                    status_code=HTTP_403_FORBIDDEN,
                    detail="JWK_invalid",
                )

            return jwt_credentials

        return None
