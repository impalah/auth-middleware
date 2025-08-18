from pydantic import Field

from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings


class CognitoAuthzProviderSettings(JWTProviderSettings):
    """Settings for Cognito provider

    Args:
        BaseModel (_type_): _description_
    """

    user_pool_id: str | None = Field(
        default=None,
        description="Secret key for JWT",
    )
    user_pool_region: str = Field(
        description="User pool region",
    )

    user_pool_client_id: str | None = Field(
        default=None,
        description="OAuth2 Client ID",
    )

    user_pool_client_secret: str | None = Field(
        default=None,
        description="OAuth2 Client Secret",
    )

    jwks_url_template: str | None = Field(
        default="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
        description="OAuth2 JWKS URL template",
    )

    jwks_cache_interval: int | None = Field(
        default=20,
        description="Cache interval refresh time (minutes)",
    )

    jwks_cache_usages: int | None = Field(
        default=1000,
        description="Number of jwks signature verification before refresh",
    )
