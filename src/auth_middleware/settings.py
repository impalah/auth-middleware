from starlette.config import Config

config = Config()


class Settings:
    """Settings for the module"""

    LOG_LEVEL: str = config("LOG_LEVEL", cast=str, default="INFO").upper()
    LOG_FORMAT: str = config(
        "LOG_FORMAT",
        cast=str,
        default="%(log_color)s%(levelname)-9s%(reset)s %(asctime)s %(name)s %(message)s",
    )

    LOGGER_NAME: str = config("LOGGER_NAME", cast=str, default="authmiddleware")

    # Disable authentication for the whole application
    AUTH_DISABLED = config("AUTH_DISABLED", cast=bool, default=False)

    AUTH_JWKS_CACHE_INTERVAL_MINUTES: int = config(
        "AUTH_JWKS_CACHE_INTERVAL_MINUTES",
        cast=int,
        default=20,
    )
    AUTH_JWKS_CACHE_USAGES: int = config(
        "AUTH_JWKS_CACHE_USAGES",
        cast=int,
        default=1000,
    )


settings = Settings()
