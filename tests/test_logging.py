import contextvars
import sys
from unittest.mock import Mock, patch
from io import StringIO

import pytest
from loguru import logger

from auth_middleware.logging import (
    add_trace_id,
    configure_logger,
    trace_id_context,
)


class TestLogging:
    """Test cases for the logging module."""

    def test_trace_id_context_default(self):
        """Test that trace_id_context has correct default value."""
        # Reset context
        trace_id_context.set(None)
        
        default_value = trace_id_context.get()
        assert default_value is None

    def test_trace_id_context_set_and_get(self):
        """Test setting and getting trace_id from context."""
        test_trace_id = "test-trace-123"
        
        token = trace_id_context.set(test_trace_id)
        
        try:
            retrieved_value = trace_id_context.get()
            assert retrieved_value == test_trace_id
        finally:
            trace_id_context.set(None)

    def test_add_trace_id_with_existing_trace(self):
        """Test add_trace_id function with existing trace ID."""
        test_trace_id = "trace-456"
        trace_id_context.set(test_trace_id)
        
        try:
            record = {"extra": {}}
            result = add_trace_id(record)
            
            assert result is True
            assert record["extra"]["trace_id"] == test_trace_id
        finally:
            trace_id_context.set(None)

    def test_add_trace_id_without_trace(self):
        """Test add_trace_id function without trace ID."""
        trace_id_context.set(None)
        
        record = {"extra": {}}
        result = add_trace_id(record)
        
        assert result is True
        assert record["extra"]["trace_id"] == "N/A"

    def test_add_trace_id_with_existing_extra(self):
        """Test add_trace_id function with existing extra data."""
        test_trace_id = "trace-789"
        trace_id_context.set(test_trace_id)
        
        try:
            record = {"extra": {"existing_key": "existing_value"}}
            result = add_trace_id(record)
            
            assert result is True
            assert record["extra"]["trace_id"] == test_trace_id
            assert record["extra"]["existing_key"] == "existing_value"
        finally:
            trace_id_context.set(None)

    def test_add_trace_id_returns_true_always(self):
        """Test that add_trace_id always returns True."""
        # Test with trace ID
        trace_id_context.set("test-trace")
        try:
            record = {"extra": {}}
            assert add_trace_id(record) is True
        finally:
            trace_id_context.set(None)
        
        # Test without trace ID
        trace_id_context.set(None)
        record = {"extra": {}}
        assert add_trace_id(record) is True

    @patch('auth_middleware.logging.logger')
    def test_configure_logger_default_settings(self, mock_logger):
        """Test configure_logger with default settings."""
        settings = {}
        
        with patch('builtins.print') as mock_print:
            configure_logger(settings)
        
        # Check that logger.remove was called
        mock_logger.remove.assert_called_once()
        
        # Check that logger.add was called
        mock_logger.add.assert_called_once()
        
        # Check the call arguments
        call_args = mock_logger.add.call_args
        assert call_args[1]['sink'] == sys.stderr
        assert call_args[1]['level'] == 'INFO'
        assert call_args[1]['filter'] == add_trace_id
        assert call_args[1]['colorize'] is False
        assert call_args[1]['enqueue'] is False
        
        # Check that print was called
        mock_print.assert_called_once()

    @patch('auth_middleware.logging.logger')
    def test_configure_logger_custom_settings(self, mock_logger):
        """Test configure_logger with custom settings."""
        settings = {
            'LOG_LEVEL': 'DEBUG',
            'LOG_FORMAT': 'Custom format: {message}',
            'LOG_COLORIZE': True,
            'LOG_ENQUEUE': True
        }
        
        with patch('builtins.print'):
            configure_logger(settings)
        
        call_args = mock_logger.add.call_args
        assert call_args[1]['level'] == 'DEBUG'
        assert call_args[1]['format'] == 'Custom format: {message}'
        assert call_args[1]['colorize'] is True
        assert call_args[1]['enqueue'] is True

    @patch('auth_middleware.logging.logger')
    def test_configure_logger_partial_settings(self, mock_logger):
        """Test configure_logger with partial settings."""
        settings = {
            'LOG_LEVEL': 'WARNING',
            'LOG_COLORIZE': True
        }
        
        with patch('builtins.print'):
            configure_logger(settings)
        
        call_args = mock_logger.add.call_args
        assert call_args[1]['level'] == 'WARNING'
        assert call_args[1]['colorize'] is True
        assert call_args[1]['enqueue'] is False  # Should use default

    @patch('auth_middleware.logging.logger')
    def test_configure_logger_default_format(self, mock_logger):
        """Test that default log format is correctly set."""
        settings = {}
        
        with patch('builtins.print'):
            configure_logger(settings)
        
        call_args = mock_logger.add.call_args
        expected_format = (
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> "
            "| <level>{level: <8}</level> | trace_id={extra[trace_id]} "
            "| <cyan>{name}</cyan>:<cyan>{function}</cyan>:"
            "<cyan>{line}</cyan> - <level>{message}</level>"
        )
        assert call_args[1]['format'] == expected_format

    @patch('auth_middleware.logging.logger')
    def test_configure_logger_all_parameters(self, mock_logger):
        """Test configure_logger sets all expected parameters."""
        settings = {'LOG_LEVEL': 'ERROR'}
        
        with patch('builtins.print'):
            configure_logger(settings)
        
        call_args = mock_logger.add.call_args
        expected_keys = {
            'sink', 'level', 'format', 'filter', 'colorize', 
            'serialize', 'backtrace', 'diagnose', 'enqueue'
        }
        
        assert set(call_args[1].keys()) == expected_keys
        assert call_args[1]['serialize'] is False
        assert call_args[1]['backtrace'] is True
        assert call_args[1]['diagnose'] is True

    def test_module_exports(self):
        """Test that module exports the expected symbols."""
        import auth_middleware.logging as logging_module
        
        expected_exports = ['logger', 'trace_id_context', 'configure_logger']
        actual_exports = logging_module.__all__
        
        assert set(actual_exports) == set(expected_exports)

    def test_imported_logger_is_loguru_logger(self):
        """Test that the imported logger is the loguru logger."""
        from auth_middleware.logging import logger as imported_logger
        from loguru import logger as loguru_logger
        
        assert imported_logger is loguru_logger

    def test_trace_id_context_is_context_var(self):
        """Test that trace_id_context is a ContextVar."""
        assert isinstance(trace_id_context, contextvars.ContextVar)
        assert trace_id_context.name == "trace_id"

    @patch('auth_middleware.logging.logger')
    def test_configure_logger_print_output(self, mock_logger):
        """Test that configure_logger prints the correct message."""
        settings = {'LOG_LEVEL': 'INFO'}
        
        with patch('builtins.print') as mock_print:
            configure_logger(settings)
        
        mock_print.assert_called_once_with("Configuring logger with settings:", settings)

    def test_context_var_isolation(self):
        """Test that trace_id_context is properly isolated between contexts."""
        import asyncio
        
        async def test_context_1():
            trace_id_context.set("context-1")
            await asyncio.sleep(0.001)  # Small delay to allow context switching
            return trace_id_context.get()
        
        async def test_context_2():
            trace_id_context.set("context-2")
            await asyncio.sleep(0.001)  # Small delay to allow context switching
            return trace_id_context.get()
        
        async def run_test():
            task1 = asyncio.create_task(test_context_1())
            task2 = asyncio.create_task(test_context_2())
            
            result1, result2 = await asyncio.gather(task1, task2)
            return result1, result2
        
        result1, result2 = asyncio.run(run_test())
        
        assert result1 == "context-1"
        assert result2 == "context-2"

    def test_add_trace_id_with_none_trace_id(self):
        """Test add_trace_id when trace_id is explicitly None."""
        trace_id_context.set(None)
        
        record = {"extra": {}}
        result = add_trace_id(record)
        
        assert result is True
        assert record["extra"]["trace_id"] == "N/A"

    def test_add_trace_id_with_empty_string_trace_id(self):
        """Test add_trace_id when trace_id is empty string."""
        trace_id_context.set("")
        
        try:
            record = {"extra": {}}
            result = add_trace_id(record)
            
            assert result is True
            assert record["extra"]["trace_id"] == "N/A"  # Empty string is falsy
        finally:
            trace_id_context.set(None)

    def test_add_trace_id_with_numeric_trace_id(self):
        """Test add_trace_id with numeric trace ID."""
        trace_id_context.set(12345)
        
        try:
            record = {"extra": {}}
            result = add_trace_id(record)
            
            assert result is True
            assert record["extra"]["trace_id"] == 12345
        finally:
            trace_id_context.set(None)

    @patch('auth_middleware.logging.logger')
    def test_configure_logger_with_boolean_strings(self, mock_logger):
        """Test configure_logger with string boolean values."""
        settings = {
            'LOG_COLORIZE': 'true',  # String instead of boolean
            'LOG_ENQUEUE': 'false'   # String instead of boolean
        }
        
        with patch('builtins.print'):
            configure_logger(settings)
        
        call_args = mock_logger.add.call_args
        # Should use the string values as-is (truthy/falsy)
        assert call_args[1]['colorize'] == 'true'
        assert call_args[1]['enqueue'] == 'false'

    def test_trace_id_context_thread_safety(self):
        """Test that trace_id_context works correctly with threading."""
        import threading
        import time
        
        results = {}
        
        def set_and_get_trace_id(thread_id):
            trace_id = f"thread-{thread_id}"
            trace_id_context.set(trace_id)
            time.sleep(0.001)  # Small delay to encourage context switching
            results[thread_id] = trace_id_context.get()
        
        threads = []
        for i in range(5):
            thread = threading.Thread(target=set_and_get_trace_id, args=(i,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Each thread should have its own context
        for i in range(5):
            assert results[i] == f"thread-{i}"
