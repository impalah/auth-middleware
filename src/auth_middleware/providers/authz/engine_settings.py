from typing import Any, Dict

from starlette.config import Config

from web_api_template.core.settings import Settings


class EngineSettings(Settings):
    """Contains the settings for the database engine

    Args:
        Settings (_type_): _description_
    """

    __settings_defaults: Dict[str, Any] = {
        "INITIALIZE": True,
        "DATABASE_URI": "None",
        "POOL_SIZE": 5,
        "MAX_OVERFLOW": -1,
        "POOL_PRE_PING": True,
        "ECHO": False,
        "POOL_RECYCLE_IN_SECONDS": 3600,
        "ECHO_POOL": False,
        "POOL_RESET_ON_RETURN": "rollback",
        "POOL_TIMEOUT_IN_SECONDS": 30,
        "POOL": "~sqlalchemy.pool.QueuePool",
    }

    def __init__(self, label: str, prefix: str = "SQLALCHEMY__"):
        """Initializes settings with the given dictionary

        Args:
            settings (Dict[str, str]): _description_
        """
        config = Config()

        for key, value in self.__settings_defaults.items():
            setattr(
                self,
                key,
                config(f"{prefix}{label}__{key}", cast=type(value), default=value),
            )
