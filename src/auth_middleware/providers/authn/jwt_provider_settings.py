from pydantic import BaseModel, Field
from typing import Optional


class JWTProviderSettings(BaseModel):
    """Base settings for JWT Provider"""

    jwt_secret_key: Optional[str] = Field(
        default=None,
        description="Secret key for JWT",
        env="JWT_SECRET_KEY",
    )
    jwt_algorithm: Optional[str] = Field(
        default="HS256",
        description="Algorithm used for JWT",
        env="JWT_ALGORITHM",
    )

    jwt_token_verification_disabled: Optional[bool] = Field(
        default=False,
        description="Disabled JWT verification Token",
        env="JWT_TOKEN_VERIFICATION_DISABLED",
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
