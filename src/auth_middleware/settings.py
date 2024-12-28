from starlette.config import Config

config = Config()


class Settings:
    """Settings for the module"""

    AUTH_MIDDLEWARE_LOG_LEVEL: str = config(
        "AUTH_MIDDLEWARE_LOG_LEVEL", cast=str, default="INFO"
    ).upper()
    AUTH_MIDDLEWARE_LOG_FORMAT: str = config(
        "AUTH_MIDDLEWARE_LOG_FORMAT",
        cast=str,
        default="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
    )

    # AUTH_MIDDLEWARE_LOGGER_NAME: str = config(
    #     "AUTH_MIDDLEWARE_LOGGER_NAME", cast=str, default="auth_middleware"
    # )

    # Disable authentication for the whole application
    AUTH_MIDDLEWARE_DISABLED = config(
        "AUTH_MIDDLEWARE_DISABLED", cast=bool, default=False
    )


settings = Settings()
