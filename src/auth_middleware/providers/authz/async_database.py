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

    @classmethod
    def initialize(cls, database_url: str, **kwargs):
        """Initializes the database connection

        Args:
            database_url (str): _description_
        """

        logger.debug(f"Initializing database connection to {database_url}")

        if cls._engine is None:
            logger.debug("Creating a new engine")
            cls._engine = create_async_engine(database_url, **kwargs)

            cls._async_session = sessionmaker(
                autocommit=False, autoflush=False, bind=cls._engine, class_=AsyncSession
            )

    def __new__(cls, *args, **kwargs):
        logger.debug("Creating a new instance of AsyncDatabase")
        if cls._instance is None:
            logger.debug("No instance. Creating a new instance of AsyncDatabase")
            cls._instance = super(AsyncDatabase, cls).__new__(cls)
        return cls._instance

    def init_engine(self):
        logger.debug("*** Initializing database engine from settings")
        if self._engine is None:
            logger.debug(
                f"*** Creating a new engine from settings. Database URI: {settings.AUTHZ_SQLALCHEMY_DATABASE_URI}"
            )
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
        logger.debug("Getting async session")
        if not self._async_session:
            logger.debug("Creating a new async session")
            self.init_engine()
        return self._async_session

    @property
    def engine(self):
        logger.debug("Getting engine")
        if not self._engine:
            logger.debug("Creating a new engine")
            self.init_engine()
        return self._engine

    @staticmethod
    @asynccontextmanager
    async def get_session():
        """Gets a session from database

        Yields:
            _type_: _description_
        """

        logger.debug("Getting session")
        # Async session returns a sessión factory (sessionmaker) and it needs () to create a session
        async with AsyncDatabase().async_session()() as session:
            yield session
