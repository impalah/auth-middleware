import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import sessionmaker

from auth_middleware.providers.authz.async_database import AsyncDatabase


class TestAsyncDatabase:
    """Test the AsyncDatabase class."""

    def setup_method(self):
        """Reset singleton instance before each test."""
        AsyncDatabase._instance = None
        AsyncDatabase._engine = None
        AsyncDatabase._async_session = None

    def test_singleton_instance(self):
        """Test that AsyncDatabase is a singleton."""
        db1 = AsyncDatabase()
        db2 = AsyncDatabase()
        
        assert db1 is db2
        assert AsyncDatabase._instance is not None

    @patch('auth_middleware.providers.authz.async_database.create_async_engine')
    @patch('auth_middleware.providers.authz.async_database.sessionmaker')
    def test_initialize_class_method(self, mock_sessionmaker, mock_create_engine):
        """Test the initialize class method."""
        mock_engine = Mock(spec=AsyncEngine)
        mock_create_engine.return_value = mock_engine
        mock_session_factory = Mock()
        mock_sessionmaker.return_value = mock_session_factory
        
        database_url = "postgresql+asyncpg://user:pass@localhost/db"
        kwargs = {"echo": True, "pool_size": 10}
        
        AsyncDatabase.initialize(database_url, **kwargs)
        
        mock_create_engine.assert_called_once_with(database_url, **kwargs)
        mock_sessionmaker.assert_called_once_with(
            autocommit=False,
            autoflush=False,
            bind=mock_engine,
            class_=AsyncSession
        )
        assert AsyncDatabase._engine is mock_engine
        assert AsyncDatabase._async_session is mock_session_factory

    @patch('auth_middleware.providers.authz.async_database.create_async_engine')
    @patch('auth_middleware.providers.authz.async_database.sessionmaker')
    def test_initialize_only_once(self, mock_sessionmaker, mock_create_engine):
        """Test that initialize only creates engine once."""
        mock_engine = Mock(spec=AsyncEngine)
        mock_create_engine.return_value = mock_engine
        
        database_url = "postgresql+asyncpg://user:pass@localhost/db"
        
        # Initialize twice
        AsyncDatabase.initialize(database_url)
        AsyncDatabase.initialize(database_url)
        
        # Should only create engine once
        mock_create_engine.assert_called_once()

    @patch('auth_middleware.providers.authz.async_database.settings')
    @patch('auth_middleware.providers.authz.async_database.create_async_engine')
    @patch('auth_middleware.providers.authz.async_database.sessionmaker')
    def test_init_engine(self, mock_sessionmaker, mock_create_engine, mock_settings):
        """Test the init_engine method."""
        mock_settings.AUTHZ_SQLALCHEMY_DATABASE_URI = "postgresql+asyncpg://test"
        mock_settings.AUTHZ_POOL_PRE_PING = True
        mock_settings.AUTHZ_POOL_SIZE = 5
        mock_settings.AUTHZ_ECHO_POOL = False
        mock_settings.AUTHZ_MAX_OVERFLOW = 10
        mock_settings.AUTHZ_POOL_RECYCLE_IN_SECONDS = 3600
        mock_settings.AUTHZ_POOL_RESET_ON_RETURN = "commit"
        mock_settings.AUTHZ_POOL_TIMEOUT_IN_SECONDS = 30
        
        mock_engine = Mock(spec=AsyncEngine)
        mock_create_engine.return_value = mock_engine
        mock_session_factory = Mock()
        mock_sessionmaker.return_value = mock_session_factory
        
        db = AsyncDatabase()
        db.init_engine()
        
        mock_create_engine.assert_called_once_with(
            "postgresql+asyncpg://test",
            pool_pre_ping=True,
            pool_size=5,
            echo=False,
            max_overflow=10,
            pool_recycle=3600,
            echo_pool=False,
            pool_reset_on_return="commit",
            pool_timeout=30
        )
        mock_sessionmaker.assert_called_once_with(
            mock_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    def test_init_engine_only_once(self):
        """Test that init_engine only creates engine once."""
        db = AsyncDatabase()
        
        with patch.object(db, '_engine', None):
            with patch('auth_middleware.providers.authz.async_database.create_async_engine') as mock_create:
                mock_engine = Mock()
                mock_create.return_value = mock_engine
                
                # Call init_engine twice
                db.init_engine()
                db._engine = mock_engine  # Simulate engine is set
                db.init_engine()
                
                # Should only create engine once
                mock_create.assert_called_once()

    def test_async_session_creates_engine_if_needed(self):
        """Test that async_session creates engine if not exists."""
        db = AsyncDatabase()
        
        with patch.object(db, 'init_engine') as mock_init:
            mock_session_factory = Mock()
            db._async_session = None
            
            # Mock init_engine to set the session
            def set_session():
                db._async_session = mock_session_factory
            mock_init.side_effect = set_session
            
            result = db.async_session()
            
            mock_init.assert_called_once()
            assert result is mock_session_factory

    def test_async_session_returns_existing(self):
        """Test that async_session returns existing session factory."""
        db = AsyncDatabase()
        mock_session_factory = Mock()
        db._async_session = mock_session_factory
        
        result = db.async_session()
        
        assert result is mock_session_factory

    def test_engine_property_creates_if_needed(self):
        """Test that engine property creates engine if not exists."""
        db = AsyncDatabase()
        
        with patch.object(db, 'init_engine') as mock_init:
            mock_engine = Mock()
            db._engine = None
            
            # Mock init_engine to set the engine
            def set_engine():
                db._engine = mock_engine
            mock_init.side_effect = set_engine
            
            result = db.engine
            
            mock_init.assert_called_once()
            assert result is mock_engine

    def test_engine_property_returns_existing(self):
        """Test that engine property returns existing engine."""
        db = AsyncDatabase()
        mock_engine = Mock()
        db._engine = mock_engine
        
        result = db.engine
        
        assert result is mock_engine

    @pytest.mark.asyncio
    async def test_get_session_context_manager(self):
        """Test the get_session static method context manager."""
        mock_session_factory = Mock()
        mock_session = AsyncMock()
        
        # Create a proper async context manager mock
        class MockAsyncContextManager:
            async def __aenter__(self):
                return mock_session
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                pass
        
        mock_session_factory.return_value = MockAsyncContextManager()
        
        # Create database instance and set session factory
        db = AsyncDatabase()
        db._async_session = mock_session_factory
        
        async with AsyncDatabase.get_session() as session:
            assert session is mock_session

    @pytest.mark.asyncio
    async def test_get_session_calls_async_session(self):
        """Test that get_session calls async_session method."""
        mock_session_factory = Mock()
        mock_session = AsyncMock()
        
        # Set up the mock to work with async context manager
        mock_session_instance = Mock()
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_instance.__aexit__ = AsyncMock()
        mock_session_factory.return_value = mock_session_instance
        
        db = AsyncDatabase()
        with patch.object(db, 'async_session', return_value=mock_session_factory):
            async with AsyncDatabase.get_session() as session:
                assert session is mock_session

    def test_new_method_logging(self):
        """Test that __new__ method logs debug messages."""
        with patch('auth_middleware.providers.authz.async_database.logger') as mock_logger:
            # First instance
            db1 = AsyncDatabase()
            
            # Second instance (should use existing)
            db2 = AsyncDatabase()
            
            # Should log for both calls
            assert mock_logger.debug.call_count >= 2
