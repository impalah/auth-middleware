"""
Comprehensive tests for auth_middleware.exceptions modules.
"""

from fastapi import HTTPException

from auth_middleware.exceptions.invalid_authorization_exception import (
    InvalidAuthorizationException,
)
from auth_middleware.exceptions.invalid_credentials_exception import (
    InvalidCredentialsException,
)
from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException


class TestInvalidTokenException:
    """Test cases for InvalidTokenException."""

    def test_invalid_token_exception_inherits_from_http_exception(self):
        """Test that InvalidTokenException inherits from HTTPException."""
        exception = InvalidTokenException(status_code=401, detail="Invalid token")

        assert isinstance(exception, HTTPException)
        assert isinstance(exception, InvalidTokenException)

    def test_invalid_token_exception_with_status_code_and_detail(self):
        """Test InvalidTokenException with status code and detail."""
        exception = InvalidTokenException(status_code=401, detail="Token expired")

        assert exception.status_code == 401
        assert exception.detail == "Token expired"

    def test_invalid_token_exception_with_headers(self):
        """Test InvalidTokenException with headers."""
        headers = {"WWW-Authenticate": "Bearer"}
        exception = InvalidTokenException(
            status_code=401, detail="Invalid token", headers=headers
        )

        assert exception.status_code == 401
        assert exception.detail == "Invalid token"
        assert exception.headers == headers

    def test_invalid_token_exception_default_values(self):
        """Test InvalidTokenException with minimal parameters."""
        exception = InvalidTokenException(status_code=401)

        assert exception.status_code == 401
        assert exception.detail == "Unauthorized"  # FastAPI HTTPException default

    def test_invalid_token_exception_str_representation(self):
        """Test string representation of InvalidTokenException."""
        exception = InvalidTokenException(status_code=401, detail="Token malformed")

        exception_str = str(exception)

        assert "401" in exception_str
        assert "Token malformed" in exception_str

    def test_invalid_token_exception_different_status_codes(self):
        """Test InvalidTokenException with different status codes."""
        # 401 Unauthorized
        exception_401 = InvalidTokenException(status_code=401, detail="Unauthorized")
        assert exception_401.status_code == 401

        # 403 Forbidden (less common but possible)
        exception_403 = InvalidTokenException(status_code=403, detail="Forbidden")
        assert exception_403.status_code == 403

    def test_invalid_token_exception_with_complex_detail(self):
        """Test InvalidTokenException with complex detail object."""
        detail = {
            "error": "invalid_token",
            "error_description": (
                "The access token provided is expired, revoked, malformed, or invalid"
            ),
            "error_uri": "https://docs.example.com/errors/invalid_token",
        }
        exception = InvalidTokenException(status_code=401, detail=detail)

        assert exception.status_code == 401
        assert exception.detail == detail
        assert exception.detail["error"] == "invalid_token"

    def test_invalid_token_exception_equality(self):
        """Test equality comparison of InvalidTokenException instances."""
        exception1 = InvalidTokenException(status_code=401, detail="Invalid token")
        exception2 = InvalidTokenException(status_code=401, detail="Invalid token")
        exception3 = InvalidTokenException(status_code=401, detail="Different message")

        # Note: HTTPException equality is based on status_code and detail
        assert exception1.status_code == exception2.status_code
        assert exception1.detail == exception2.detail
        assert exception1.detail != exception3.detail


class TestInvalidCredentialsException:
    """Test cases for InvalidCredentialsException."""

    def test_invalid_credentials_exception_inherits_from_http_exception(self):
        """Test that InvalidCredentialsException inherits from HTTPException."""
        exception = InvalidCredentialsException(
            status_code=401, detail="Invalid credentials"
        )

        assert isinstance(exception, HTTPException)
        assert isinstance(exception, InvalidCredentialsException)

    def test_invalid_credentials_exception_with_status_code_and_detail(self):
        """Test InvalidCredentialsException with status code and detail."""
        exception = InvalidCredentialsException(
            status_code=401, detail="Username or password incorrect"
        )

        assert exception.status_code == 401
        assert exception.detail == "Username or password incorrect"

    def test_invalid_credentials_exception_with_headers(self):
        """Test InvalidCredentialsException with headers."""
        headers = {"WWW-Authenticate": 'Basic realm="API"'}
        exception = InvalidCredentialsException(
            status_code=401, detail="Invalid credentials", headers=headers
        )

        assert exception.status_code == 401
        assert exception.detail == "Invalid credentials"
        assert exception.headers == headers

    def test_invalid_credentials_exception_different_scenarios(self):
        """Test InvalidCredentialsException for different authentication scenarios."""
        # Missing credentials
        missing_creds = InvalidCredentialsException(
            status_code=401, detail="Missing authentication credentials"
        )
        assert missing_creds.detail == "Missing authentication credentials"

        # Malformed credentials
        malformed_creds = InvalidCredentialsException(
            status_code=400, detail="Malformed credentials format"
        )
        assert malformed_creds.status_code == 400

        # Expired credentials
        expired_creds = InvalidCredentialsException(
            status_code=401, detail="Credentials have expired"
        )
        assert expired_creds.detail == "Credentials have expired"

    def test_invalid_credentials_exception_str_representation(self):
        """Test string representation of InvalidCredentialsException."""
        exception = InvalidCredentialsException(
            status_code=401, detail="Authentication failed"
        )

        exception_str = str(exception)

        assert "401" in exception_str
        assert "Authentication failed" in exception_str


class TestInvalidAuthorizationException:
    """Test cases for InvalidAuthorizationException."""

    def test_invalid_authorization_exception_inherits_from_http_exception(self):
        """Test that InvalidAuthorizationException inherits from HTTPException."""
        exception = InvalidAuthorizationException(
            status_code=403, detail="Access denied"
        )

        assert isinstance(exception, HTTPException)
        assert isinstance(exception, InvalidAuthorizationException)

    def test_invalid_authorization_exception_with_status_code_and_detail(self):
        """Test InvalidAuthorizationException with status code and detail."""
        exception = InvalidAuthorizationException(
            status_code=403, detail="Insufficient permissions"
        )

        assert exception.status_code == 403
        assert exception.detail == "Insufficient permissions"

    def test_invalid_authorization_exception_with_headers(self):
        """Test InvalidAuthorizationException with headers."""
        headers = {"Content-Type": "application/json"}
        exception = InvalidAuthorizationException(
            status_code=403, detail="Access denied", headers=headers
        )

        assert exception.status_code == 403
        assert exception.detail == "Access denied"
        assert exception.headers == headers

    def test_invalid_authorization_exception_different_scenarios(self):
        """Test InvalidAuthorizationException for different authorization scenarios."""
        # Insufficient permissions
        insufficient_perms = InvalidAuthorizationException(
            status_code=403, detail="User lacks required permissions"
        )
        assert insufficient_perms.detail == "User lacks required permissions"

        # Wrong role/group
        wrong_role = InvalidAuthorizationException(
            status_code=403, detail="User not in required group"
        )
        assert wrong_role.detail == "User not in required group"

        # Resource access denied
        resource_denied = InvalidAuthorizationException(
            status_code=403, detail="Access to resource denied"
        )
        assert resource_denied.detail == "Access to resource denied"

    def test_invalid_authorization_exception_with_detailed_info(self):
        """Test InvalidAuthorizationException with detailed authorization info."""
        detail = {
            "error": "insufficient_scope",
            "error_description": "The request requires higher privileges than provided",
            "required_permissions": ["admin", "write"],
            "user_permissions": ["read"],
        }
        exception = InvalidAuthorizationException(status_code=403, detail=detail)

        assert exception.status_code == 403
        assert exception.detail == detail
        assert exception.detail["required_permissions"] == ["admin", "write"]

    def test_invalid_authorization_exception_str_representation(self):
        """Test string representation of InvalidAuthorizationException."""
        exception = InvalidAuthorizationException(
            status_code=403, detail="Operation not allowed"
        )

        exception_str = str(exception)

        assert "403" in exception_str
        assert "Operation not allowed" in exception_str


class TestExceptionsIntegration:
    """Integration tests for all exception types."""

    def test_exception_hierarchy(self):
        """Test that all custom exceptions inherit from HTTPException."""
        token_exception = InvalidTokenException(status_code=401, detail="Token error")
        creds_exception = InvalidCredentialsException(
            status_code=401, detail="Creds error"
        )
        authz_exception = InvalidAuthorizationException(
            status_code=403, detail="Authz error"
        )

        exceptions = [token_exception, creds_exception, authz_exception]

        for exception in exceptions:
            assert isinstance(exception, HTTPException)

    def test_exception_different_status_codes(self):
        """Test exceptions with different status codes."""
        exceptions = [
            InvalidTokenException(status_code=401, detail="Unauthorized"),
            InvalidCredentialsException(status_code=400, detail="Bad Request"),
            InvalidAuthorizationException(status_code=403, detail="Forbidden"),
        ]

        status_codes = [exc.status_code for exc in exceptions]
        assert status_codes == [401, 400, 403]

    def test_exception_serialization(self):
        """Test that exceptions can be properly serialized."""
        import json

        exception = InvalidTokenException(status_code=401, detail="Token expired")

        # Test that exception details can be serialized
        detail_json = json.dumps(
            {"status_code": exception.status_code, "detail": exception.detail}
        )
        parsed = json.loads(detail_json)

        assert parsed["status_code"] == 401
        assert parsed["detail"] == "Token expired"

    def test_exception_handling_patterns(self):
        """Test common exception handling patterns."""

        def handle_auth_exception(exception):
            if isinstance(exception, InvalidTokenException):
                return "TOKEN_ERROR"
            elif isinstance(exception, InvalidCredentialsException):
                return "CREDENTIALS_ERROR"
            elif isinstance(exception, InvalidAuthorizationException):
                return "AUTHORIZATION_ERROR"
            else:
                return "UNKNOWN_ERROR"

        token_exc = InvalidTokenException(status_code=401, detail="Token error")
        creds_exc = InvalidCredentialsException(status_code=401, detail="Creds error")
        authz_exc = InvalidAuthorizationException(status_code=403, detail="Authz error")

        assert handle_auth_exception(token_exc) == "TOKEN_ERROR"
        assert handle_auth_exception(creds_exc) == "CREDENTIALS_ERROR"
        assert handle_auth_exception(authz_exc) == "AUTHORIZATION_ERROR"

    def test_exception_with_none_values(self):
        """Test exceptions with None values for optional parameters."""
        # Test with minimal required parameters
        token_exc = InvalidTokenException(status_code=401)
        creds_exc = InvalidCredentialsException(status_code=401)
        authz_exc = InvalidAuthorizationException(status_code=403)

        # FastAPI HTTPException provides default messages based on status code
        assert token_exc.detail == "Unauthorized"
        assert creds_exc.detail == "Unauthorized"
        assert authz_exc.detail == "Forbidden"

        assert token_exc.headers is None
        assert creds_exc.headers is None
        assert authz_exc.headers is None

    def test_exception_with_custom_headers(self):
        """Test exceptions with custom headers."""
        custom_headers = {
            "X-Error-Code": "AUTH_001",
            "X-Request-ID": "req-123456",
            "Content-Type": "application/json",
        }

        exception = InvalidTokenException(
            status_code=401, detail="Custom token error", headers=custom_headers
        )

        assert exception.headers == custom_headers
        assert exception.headers["X-Error-Code"] == "AUTH_001"
        assert exception.headers["X-Request-ID"] == "req-123456"

    def test_exception_immutability(self):
        """Test that exception instances maintain their values."""
        exception = InvalidTokenException(status_code=401, detail="Original message")

        original_status = exception.status_code
        original_detail = exception.detail

        # Create another exception to ensure original is unchanged
        InvalidTokenException(status_code=403, detail="Different message")

        assert exception.status_code == original_status
        assert exception.detail == original_detail
