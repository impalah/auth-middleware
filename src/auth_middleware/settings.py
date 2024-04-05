from starlette.config import Config

config = Config()


class Settings:
    """Settings for the module"""

    AUTH_MIDDLEWARE_LOG_LEVEL: str = config("AUTH_MIDDLEWARE_LOG_LEVEL", cast=str, default="INFO").upper()
    AUTH_MIDDLEWARE_LOG_FORMAT: str = config(
        "AUTH_MIDDLEWARE_LOG_FORMAT",
        cast=str,
        default="%(log_color)s%(levelname)-9s%(reset)s %(asctime)s %(name)s %(message)s",
    )

    AUTH_MIDDLEWARE_LOGGER_NAME: str = config("AUTH_MIDDLEWARE_LOGGER_NAME", cast=str, default="auth_middleware")

    # Disable authentication for the whole application
    AUTH_MIDDLEWARE_DISABLED = config("AUTH_MIDDLEWARE_DISABLED", cast=bool, default=False)

    AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES: int = config(
        "AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES",
        cast=int,
        default=20,
    )
    AUTH_MIDDLEWARE_JWKS_CACHE_USAGES: int = config(
        "AUTH_MIDDLEWARE_JWKS_CACHE_USAGES",
        cast=int,
        default=1000,
    )


settings = Settings()
