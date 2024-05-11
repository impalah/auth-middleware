from typing import Optional

from starlette.config import Config

from auth_middleware.settings import Settings

config = Config()


class ModuleSettings(Settings):
    """Settings for the module"""

    AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH: str = config(
        "AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH",
        cast=str,
        default=None,
    )


settings = ModuleSettings()
