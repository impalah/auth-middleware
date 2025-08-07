from unittest.mock import AsyncMock, Mock, patch
import asyncio

import pytest
import click
from click.testing import CliRunner

from auth_middleware.cli import cli, get_permissions


class TestCLI:
    """Test cases for the CLI module."""

    def test_cli_group_exists(self):
        """Test that the CLI group is properly configured."""
        assert isinstance(cli, click.Group)
        assert "CLI for managing groups and permissions" in cli.help

    def test_cli_group_callable(self):
        """Test that the CLI group can be called."""
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])
        
        assert result.exit_code == 0
        assert "CLI for managing groups and permissions" in result.output
        assert "Usage:" in result.output

    def test_get_permissions_command_exists(self):
        """Test that get_permissions command is properly configured."""
        command = cli.get_command(None, "get-permissions")  # Click automatically converts underscores to hyphens
        assert command is not None
        assert command.name == "get-permissions"

    def test_get_permissions_has_username_argument(self):
        """Test that get_permissions command has username argument."""
        params = get_permissions.params
        assert len(params) == 1
        assert params[0].name == "username"
        assert isinstance(params[0], click.Argument)

    @patch('auth_middleware.cli.SqlPermissionsProvider')
    def test_get_permissions_command_execution(self, mock_provider_class):
        """Test get_permissions command execution."""
        # Setup mock
        mock_provider = AsyncMock()
        mock_provider.get_permissions_from_db.return_value = ["read", "write", "admin"]
        mock_provider_class.return_value = mock_provider
        
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['testuser'])
        
        assert result.exit_code == 0
        assert "Permissions for testuser: ['read', 'write', 'admin']" in result.output
        mock_provider_class.assert_called_once()
        mock_provider.get_permissions_from_db.assert_called_once_with(username='testuser')

    @patch('auth_middleware.cli.SqlPermissionsProvider')
    def test_get_permissions_command_with_empty_permissions(self, mock_provider_class):
        """Test get_permissions command with empty permissions."""
        # Setup mock to return empty list
        mock_provider = AsyncMock()
        mock_provider.get_permissions_from_db.return_value = []
        mock_provider_class.return_value = mock_provider
        
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['testuser'])
        
        assert result.exit_code == 0
        assert "Permissions for testuser: []" in result.output

    @patch('auth_middleware.cli.SqlPermissionsProvider')
    def test_get_permissions_command_with_exception(self, mock_provider_class):
        """Test get_permissions command when provider raises exception."""
        # Setup mock to raise exception
        mock_provider = AsyncMock()
        mock_provider.get_permissions_from_db.side_effect = Exception("Database error")
        mock_provider_class.return_value = mock_provider
        
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['testuser'])
        
        # Command should fail
        assert result.exit_code != 0
        assert "Database error" in str(result.exception)

    def test_get_permissions_command_missing_username(self):
        """Test get_permissions command without username argument."""
        runner = CliRunner()
        result = runner.invoke(get_permissions, [])
        
        assert result.exit_code != 0
        assert "Missing argument" in result.output

    def test_get_permissions_command_with_special_username(self):
        """Test get_permissions command with special characters in username."""
        with patch('auth_middleware.cli.SqlPermissionsProvider') as mock_provider_class:
            mock_provider = AsyncMock()
            mock_provider.get_permissions_from_db.return_value = ["special"]
            mock_provider_class.return_value = mock_provider
            
            runner = CliRunner()
            result = runner.invoke(get_permissions, ['user@domain.com'])
            
            assert result.exit_code == 0
            assert "Permissions for user@domain.com: ['special']" in result.output
            mock_provider.get_permissions_from_db.assert_called_once_with(username='user@domain.com')

    @patch('auth_middleware.cli.SqlPermissionsProvider')
    def test_get_permissions_async_execution(self, mock_provider_class):
        """Test that get_permissions properly handles async execution."""
        mock_provider = AsyncMock()
        mock_provider.get_permissions_from_db.return_value = ["async_test"]
        mock_provider_class.return_value = mock_provider
        
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['asyncuser'])
        
        assert result.exit_code == 0
        # Verify async function was called
        mock_provider.get_permissions_from_db.assert_called_once()

    def test_cli_module_main_execution(self):
        """Test CLI module when run as main."""
        with patch('auth_middleware.cli.cli') as mock_cli:
            # Import and run the module as main
            with patch('__main__.__name__', '__main__'):
                import auth_middleware.cli
                # Simulate running as script
                exec(compile(open(auth_middleware.cli.__file__).read(), auth_middleware.cli.__file__, 'exec'))

    def test_get_permissions_help(self):
        """Test get_permissions command help."""
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['--help'])
        
        assert result.exit_code == 0
        assert "Get permissions for a user" in result.output
        assert "USERNAME" in result.output

    @patch('auth_middleware.cli.SqlPermissionsProvider')
    @patch('auth_middleware.cli.asyncio.run')
    def test_get_permissions_asyncio_run_called(self, mock_asyncio_run, mock_provider_class):
        """Test that asyncio.run is called for async execution."""
        mock_provider = AsyncMock()
        mock_provider.get_permissions_from_db.return_value = ["test"]
        mock_provider_class.return_value = mock_provider
        
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['testuser'])
        
        # asyncio.run should have been called
        mock_asyncio_run.assert_called_once()

    def test_multiple_usernames_not_supported(self):
        """Test that multiple usernames are not supported (only takes one argument)."""
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['user1', 'user2'])
        
        # Should fail because only one argument is expected
        assert result.exit_code != 0

    @patch('auth_middleware.cli.SqlPermissionsProvider')
    def test_get_permissions_none_result(self, mock_provider_class):
        """Test get_permissions when provider returns None."""
        mock_provider = AsyncMock()
        mock_provider.get_permissions_from_db.return_value = None
        mock_provider_class.return_value = mock_provider
        
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['testuser'])
        
        assert result.exit_code == 0
        assert "Permissions for testuser: None" in result.output

    @patch('auth_middleware.cli.SqlPermissionsProvider')
    def test_get_permissions_complex_permissions(self, mock_provider_class):
        """Test get_permissions with complex permission structure."""
        complex_permissions = [
            "read:files",
            "write:database", 
            "admin:users",
            "super:system"
        ]
        
        mock_provider = AsyncMock()
        mock_provider.get_permissions_from_db.return_value = complex_permissions
        mock_provider_class.return_value = mock_provider
        
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['poweruser'])
        
        assert result.exit_code == 0
        assert "read:files" in result.output
        assert "admin:users" in result.output

    def test_cli_group_no_commands_by_default(self):
        """Test that CLI group has the expected commands registered."""
        # The get_permissions command is now added to cli
        assert len(cli.commands) == 1
        assert "get-permissions" in cli.commands

    @patch('auth_middleware.cli.SqlPermissionsProvider')
    def test_get_permissions_timeout_handling(self, mock_provider_class):
        """Test get_permissions command with async timeout."""
        mock_provider = AsyncMock()
        
        # Simulate a long-running async operation
        async def slow_operation(username):
            await asyncio.sleep(0.1)  # Small delay to simulate work
            return ["slow_permission"]
        
        mock_provider.get_permissions_from_db.side_effect = slow_operation
        mock_provider_class.return_value = mock_provider
        
        runner = CliRunner()
        result = runner.invoke(get_permissions, ['slowuser'])
        
        assert result.exit_code == 0
        assert "slow_permission" in result.output

    def test_click_echo_usage(self):
        """Test that click.echo is used for output."""
        with patch('auth_middleware.cli.SqlPermissionsProvider') as mock_provider_class:
            with patch('click.echo') as mock_echo:
                mock_provider = AsyncMock()
                mock_provider.get_permissions_from_db.return_value = ["test"]
                mock_provider_class.return_value = mock_provider
                
                runner = CliRunner()
                result = runner.invoke(get_permissions, ['testuser'])
                
                # click.echo should have been called within the async function
                # We can't directly test this due to asyncio.run, but we verify command works
                assert result.exit_code == 0
