from typing import Optional

from starlette.config import Config

from auth_middleware.settings import Settings

config = Config()


class CognitoSettings(Settings):
    """Settings for the cognito module"""

    AUTH_PROVIDER_AWS_COGNITO_USER_POOL_ID: Optional[str] = config(
        "AUTH_PROVIDER_AWS_COGNITO_USER_POOL_ID",
        cast=str,
        default=None,
    )

    AUTH_PROVIDER_AWS_COGNITO_USER_POOL_REGION: Optional[str] = config(
        "AUTH_PROVIDER_AWS_COGNITO_USER_POOL_REGION",
        cast=str,
        default=None,
    )

    AUTH_PROVIDER_AWS_COGNITO_JWKS_URL_TEMPLATE: str = config(
        "AUTH_PROVIDER_AWS_COGNITO_JWKS_URL_TEMPLATE",
        cast=str,
        default="https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json",
    )

    AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_ID: Optional[str] = config(
        "AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_ID",
        cast=str,
        default=None,
    )

    AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_SECRET: Optional[str] = config(
        "AUTH_PROVIDER_AWS_COGNITO_USER_POOL_CLIENT_SECRET",
        cast=str,
        default=None,
    )

    AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED = config(
        "AUTH_PROVIDER_AWS_COGNITO_TOKEN_VERIFICATION_DISABLED",
        cast=bool,
        default=False,
    )


settings = CognitoSettings()
