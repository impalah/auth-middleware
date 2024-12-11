from pydantic import BaseModel, Field
from typing import Optional

from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings


class CognitoAuthzProviderSettings(JWTProviderSettings):
    """Settings for Cognito provider

    Args:
        BaseModel (_type_): _description_
    """

    user_pool_id: Optional[str] = Field(
        default=None,
        description="Secret key for JWT",
        env="USER_POOL_ID",
    )
    user_pool_region: str = Field(
        ...,
        description="User pool region",
        env="USER_POOL_REGION",
    )

    user_pool_client_id: Optional[str] = Field(
        default=None,
        description="OAuth2 Client ID",
        env="USER_POOL_CLIENT_ID",
    )

    user_pool_client_secret: Optional[str] = Field(
        default=None,
        description="OAuth2 Client Secret",
        env="USER_POOL_CLIENT_SECRET",
    )

    jwks_url_template: Optional[str] = Field(
        default="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
        description="OAuth2 JWKS URL template",
        env="JWKS_URL_TEMPLATE",
    )

    jwks_cache_interval: Optional[int] = Field(
        default=20,
        description="Cache interval refresh time (minutes)",
        env="JWKS_CACHE_INTERVAL",
    )

    jwks_cache_usages: Optional[int] = Field(
        default=1000,
        description="Number of jwks signature verification before refresh",
        env="JWKS_CACHE_USAGES",
    )
