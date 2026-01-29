from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class JWTProviderSettings(BaseSettings):
    """Base settings for JWT Provider"""

    model_config = SettingsConfigDict(
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

    # JWKS cache strategy settings
    jwks_cache_strategy: Literal["time", "usage", "both"] = Field(
        default="both",
        description="JWKS cache refresh strategy: time-based, usage-based, or both",
    )

    jwks_background_refresh: bool = Field(
        default=True,
        description="Enable background refresh of JWKS before cache expires",
    )

    jwks_background_refresh_threshold: float = Field(
        default=0.8,
        description="Threshold (0.0-1.0) of cache lifetime to trigger background refresh",
        ge=0.0,
        le=1.0,
    )
