from pydantic import ConfigDict, Field
from pydantic_settings import BaseSettings


class JWTProviderSettings(BaseSettings):
    """Base settings for JWT Provider"""

    model_config = ConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    jwt_secret_key: str | None = Field(
        default=None,
        description="Secret key for JWT",
    )
    jwt_algorithm: str | None = Field(
        default="HS256",
        description="Algorithm used for JWT",
    )

    jwt_token_verification_disabled: bool | None = Field(
        default=False,
        description="Disabled JWT verification Token",
    )
