from starlette.config import Config

from auth_middleware.settings import Settings

config = Config()


class ModuleSettings(Settings):
    """Settings for the module"""

    AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID: str | None = config(
        "AUTH_PROVIDER_AZURE_ENTRA_ID_TENANT_ID",
        cast=str,
        default=None,
    )

    # The audience id is the client id of the application
    AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID: str | None = config(
        "AUTH_PROVIDER_AZURE_ENTRA_ID_AUDIENCE_ID",
        cast=str,
        default=None,
    )

    AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE: str = config(
        "AUTH_PROVIDER_AZURE_ENTRA_ID_JWKS_URL_TEMPLATE",
        cast=str,
        default="https://login.microsoftonline.com/{}/v2.0/.well-known/openid-configuration",
    )

    # Clock-skew allowance (seconds) applied when validating registered
    # claims such as exp/nbf, to tolerate small time differences between
    # servers.
    AUTH_PROVIDER_AZURE_ENTRA_ID_LEEWAY: int = config(
        "AUTH_PROVIDER_AZURE_ENTRA_ID_LEEWAY",
        cast=int,
        default=0,
    )


settings = ModuleSettings()
