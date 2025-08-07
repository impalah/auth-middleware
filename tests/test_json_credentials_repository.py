import json
import os
import pytest
import tempfile
from unittest.mock import patch, mock_open

from auth_middleware.repository.json_credentials_repository import JsonCredentialsRepository
from auth_middleware.types.user_credentials import UserCredentials


class TestJsonCredentialsRepository:
    """Test the JsonCredentialsRepository class."""

    @pytest.fixture
    def sample_json_data(self):
        """Sample JSON data for testing."""
        return {
            "user1": {
                "name": "John Doe",
                "hashed_pwd": "hashedpassword123",
                "groups": ["admin", "user"],
                "email": "john@example.com"
            },
            "user2": {
                "name": "Jane Smith",
                "hashed_pwd": "hashedpassword456",
                "groups": ["user"],
                "email": "jane@example.com"
            },
            "user3": {
                "name": "Bob Wilson",
                "hashed_pwd": "hashedpassword789"
                # No groups or email for this user
            }
        }

    @pytest.fixture
    def temp_json_file(self, sample_json_data):
        """Create a temporary JSON file for testing."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(sample_json_data, f)
            temp_file_path = f.name
        
        yield temp_file_path
        
        # Cleanup
        os.unlink(temp_file_path)

    @patch('auth_middleware.repository.json_credentials_repository.settings')
    def test_init_loads_json_file(self, mock_settings, temp_json_file, sample_json_data):
        """Test that __init__ loads the JSON file correctly."""
        mock_settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH = os.path.basename(temp_json_file)
        
        with patch('os.getcwd', return_value=os.path.dirname(temp_json_file)):
            repo = JsonCredentialsRepository()
            assert repo._database == sample_json_data

    @patch('auth_middleware.repository.json_credentials_repository.settings')
    def test_init_with_file_not_found(self, mock_settings):
        """Test __init__ behavior when file is not found."""
        mock_settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH = "nonexistent.json"
        
        with pytest.raises(FileNotFoundError):
            JsonCredentialsRepository()

    @patch('auth_middleware.repository.json_credentials_repository.settings')
    def test_init_with_invalid_json(self, mock_settings):
        """Test __init__ behavior with invalid JSON."""
        mock_settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH = "invalid.json"
        
        with patch('builtins.open', mock_open(read_data="invalid json content")):
            with pytest.raises(json.JSONDecodeError):
                JsonCredentialsRepository()

    @pytest.mark.asyncio
    @patch('auth_middleware.repository.json_credentials_repository.settings')
    async def test_get_by_id_existing_user(self, mock_settings, temp_json_file):
        """Test getting an existing user by ID."""
        mock_settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH = os.path.basename(temp_json_file)
        
        with patch('os.getcwd', return_value=os.path.dirname(temp_json_file)):
            repo = JsonCredentialsRepository()
            user = await repo.get_by_id(id="user1")
            
            assert user is not None
            assert isinstance(user, UserCredentials)
            assert user.id == "user1"
            assert user.name == "John Doe"
            assert user.hashed_password == "hashedpassword123"
            assert user.email == "john@example.com"

    @pytest.mark.asyncio
    @patch('auth_middleware.repository.json_credentials_repository.settings')
    async def test_get_by_id_nonexistent_user(self, mock_settings, temp_json_file):
        """Test getting a non-existent user by ID."""
        mock_settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH = os.path.basename(temp_json_file)
        
        with patch('os.getcwd', return_value=os.path.dirname(temp_json_file)):
            repo = JsonCredentialsRepository()
            user = await repo.get_by_id(id="nonexistent")
            
            assert user is None

    @pytest.mark.asyncio
    @patch('auth_middleware.repository.json_credentials_repository.settings')
    async def test_get_by_id_user_without_optional_fields(self, mock_settings, temp_json_file):
        """Test getting a user that doesn't have optional fields."""
        mock_settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH = os.path.basename(temp_json_file)
        
        with patch('os.getcwd', return_value=os.path.dirname(temp_json_file)):
            repo = JsonCredentialsRepository()
            user = await repo.get_by_id(id="user3")
            
            assert user is not None
            assert user.id == "user3"
            assert user.name == "Bob Wilson"
            assert user.hashed_password == "hashedpassword789"
            assert user.email is None

    def test_repository_inheritance(self):
        """Test that JsonCredentialsRepository inherits from CredentialsRepository."""
        from auth_middleware.repository.credentials_repository import CredentialsRepository
        
        # Mock the file operations to avoid actual file access
        with patch('builtins.open', mock_open(read_data='{"test": {"name": "Test", "hashed_pwd": "pwd"}}')):
            with patch('auth_middleware.repository.json_credentials_repository.settings') as mock_settings:
                mock_settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH = "test.json"
                repo = JsonCredentialsRepository()
                assert isinstance(repo, CredentialsRepository)

    @patch('auth_middleware.repository.json_credentials_repository.settings')
    def test_file_path_construction(self, mock_settings):
        """Test that file path is constructed correctly."""
        mock_settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH = "credentials.json"
        
        with patch('os.getcwd', return_value="/test/path"):
            with patch('builtins.open', mock_open(read_data='{}')) as mock_file:
                JsonCredentialsRepository()
                
                # Verify the file path construction
                expected_path = os.path.join("/test/path", "credentials.json")
                mock_file.assert_called_once_with(expected_path)
