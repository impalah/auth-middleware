from typing import Optional

from starlette.config import Config

from auth_middleware.settings import Settings

config = Config()


class ModuleSettings(Settings):
    """Settings for the module"""

    AWS_COGNITO_USER_POOL_ID: Optional[str] = config(
        "AWS_COGNITO_USER_POOL_ID",
        cast=str,
        default=None,
    )

    AWS_COGNITO_USER_POOL_REGION: Optional[str] = config(
        "AWS_COGNITO_USER_POOL_REGION",
        cast=str,
        default=None,
    )

    AWS_COGNITO_JWKS_URL_TEMPLATE: str = config(
        "AWS_COGNITO_JWKS_URL_TEMPLATE",
        cast=str,
        default="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
    )

    AWS_COGNITO_USER_POOL_CLIENT_ID: Optional[str] = config(
        "AWS_COGNITO_USER_POOL_CLIENT_ID",
        cast=str,
        default=None,
    )

    AWS_COGNITO_USER_POOL_CLIENT_SECRET: Optional[str] = config(
        "AWS_COGNITO_USER_POOL_CLIENT_SECRET",
        cast=str,
        default=None,
    )


settings = ModuleSettings()
