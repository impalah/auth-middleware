from starlette.config import Config

from auth_middleware.settings import Settings


config = Config()


class AsyncDatabaseSettings(Settings):
    """Settings for the async database module"""

    AUTHZ_SQLALCHEMY_DATABASE_URI: str = config(
        "AUTHZ_SQLALCHEMY_DATABASE_URI", cast=str, default="nada"
    )

    AUTHZ_POOL_SIZE: int = config(
        "AUTHZ_POOL_SIZE",
        cast=int,
        default=5,
    )

    AUTHZ_MAX_OVERFLOW: int = config(
        "AUTHZ_MAX_OVERFLOW",
        cast=int,
        default=-1,
    )

    AUTHZ_POOL_PRE_PING = config("AUTHZ_POOL_PRE_PING", cast=bool, default=True)

    AUTHZ_ECHO_POOL = config("AUTHZ_ECHO_POOL", cast=bool, default=False)

    AUTHZ_POOL_RECYCLE_IN_SECONDS: int = config(
        "AUTHZ_POOL_RECYCLE_IN_SECONDS",
        cast=int,
        default=3600,
    )

    AUTHZ_POOL_RESET_ON_RETURN: str = config(
        "AUTHZ_POOL_RESET_ON_RETURN",
        cast=str,
        default="rollback",
    )

    AUTHZ_POOL_TIMEOUT_IN_SECONDS: int = config(
        "AUTHZ_POOL_TIMEOUT_IN_SECONDS",
        cast=int,
        default=30,
    )

    AUTHZ_POOL: str = config(
        "AUTHZ_POOL",
        cast=str,
        default="~sqlalchemy.pool.QueuePool",
    )


settings = AsyncDatabaseSettings()
