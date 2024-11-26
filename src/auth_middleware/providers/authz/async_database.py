from contextlib import asynccontextmanager
from typing import Dict, Optional

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from auth_middleware.logging import logger
from .sql_base_model import metadata

from .async_database_settings import settings


class AsyncDatabase:
    """Async database connection manager

    Returns:
        _type_: _description_

    Yields:
        _type_: _description_
    """

    _instance = None
    _engine: AsyncEngine = None
    _async_session: AsyncSession = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(AsyncDatabase, cls).__new__(cls)
        return cls._instance

    def init_engine(self):
        if self._engine is None:
            self._engine = create_async_engine(
                settings.AUTHZ_SQLALCHEMY_DATABASE_URI,
                pool_pre_ping=settings.AUTHZ_POOL_PRE_PING,
                pool_size=settings.AUTHZ_POOL_SIZE,
                echo=settings.AUTHZ_ECHO_POOL,
                max_overflow=settings.AUTHZ_MAX_OVERFLOW,
                pool_recycle=settings.AUTHZ_POOL_RECYCLE_IN_SECONDS,
                echo_pool=settings.AUTHZ_ECHO_POOL,
                pool_reset_on_return=settings.AUTHZ_POOL_RESET_ON_RETURN,
                pool_timeout=settings.AUTHZ_POOL_TIMEOUT_IN_SECONDS,
            )
            self._async_session = sessionmaker(
                self._engine, class_=AsyncSession, expire_on_commit=False
            )

    def async_session(self):
        if not self._async_session:
            self.init_engine()
        return self._async_session

    @property
    def engine(self):
        if not self._engine:
            self.init_engine()
        return self._engine

    @staticmethod
    @asynccontextmanager
    async def get_session():
        """Gets a session from database

        Yields:
            _type_: _description_
        """
        # Async session returns a sessión factory (sessionmaker) and it needs () to create a session
        async with AsyncDatabase().async_session()() as session:
            yield session
