from starlette.config import Config
from typing import Optional

config = Config()


class DemoSettings:
    """Settings for the demo"""

    USER_POOL_DOMAIN: Optional[str] = config(
        "USER_POOL_DOMAIN",
        cast=str,
        default=None,
    )

    USER_POOL_ID: Optional[str] = config(
        "USER_POOL_ID",
        cast=str,
        default=None,
    )

    AWS_REGION: Optional[str] = config(
        "AWS_REGION",
        cast=str,
        default=None,
    )

    USER_POOL_CLIENT_ID: Optional[str] = config(
        "USER_POOL_CLIENT_ID",
        cast=str,
        default=None,
    )

    LOG_LEVEL: str = config("LOG_LEVEL", cast=str, default="INFO").upper()

    # Disable authentication for the whole application
    TOKEN_VERIFICATION_DISABLED = config(
        "TOKEN_VERIFICATION_DISABLED", cast=bool, default=False
    )

    SQLALCHEMY_DATABASE_URI: Optional[str] = config(
        "SQLALCHEMY_DATABASE_URI",
        cast=str,
        default=None,
    )


settings = DemoSettings()
