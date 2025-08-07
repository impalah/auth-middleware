"""
Comprehensive tests for auth_middleware.types.jwt module.
"""

from auth_middleware.types.jwt import JWKS, JWTAuthorizationCredentials


class TestJWKS:
    """Test cases for JWKS class."""

    def test_jwks_creation_with_keys(self):
        """Test JWKS creation with key list."""
        keys = [
            {"kid": "key1", "kty": "RSA", "alg": "RS256"},
            {"kid": "key2", "kty": "RSA", "alg": "RS256"},
        ]
        jwks = JWKS(keys=keys)

        assert jwks.keys == keys
        assert len(jwks.keys) == 2
        assert jwks.keys[0]["kid"] == "key1"
        assert jwks.keys[1]["kid"] == "key2"

    def test_jwks_creation_empty_keys(self):
        """Test JWKS creation with empty key list."""
        jwks = JWKS(keys=[])

        assert jwks.keys == []
        assert len(jwks.keys) == 0

    def test_jwks_creation_without_keys(self):
        """Test JWKS creation without keys parameter (should use default)."""
        jwks = JWKS()

        assert jwks.keys == []

    def test_jwks_keys_with_complex_structure(self):
        """Test JWKS with complex key structures."""
        complex_keys = [
            {
                "kid": "rsa-key-1",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt",
                "e": "AQAB",
                "x5c": ["MIIC+DCCAeCgAwIBAgIJBIGjYW6hFpn2MA0GCSqGSIb3DQ..."],
                "x5t": "R8hGBrABZGcXWXP6CyEnCSTDWKQ",
            },
            {
                "kid": "ec-key-1",
                "kty": "EC",
                "alg": "ES256",
                "use": "sig",
                "crv": "P-256",
                "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGHwHitJBcBmXQ",
                "y": "y77As5vbZdIGNHjFK5ey-3ey0OgxRkHJopXz9vhbKVw",
            },
        ]

        jwks = JWKS(keys=complex_keys)

        assert len(jwks.keys) == 2
        assert jwks.keys[0]["kty"] == "RSA"
        assert jwks.keys[1]["kty"] == "EC"
        assert jwks.keys[0]["alg"] == "RS256"
        assert jwks.keys[1]["alg"] == "ES256"

    def test_jwks_keys_modification(self):
        """Test JWKS keys list modification."""
        initial_keys = [{"kid": "key1", "kty": "RSA"}]
        jwks = JWKS(keys=initial_keys)

        # Modify the original list
        initial_keys.append({"kid": "key2", "kty": "EC"})

        # JWKS should maintain its own copy
        assert len(jwks.keys) == 1
        assert jwks.keys[0]["kid"] == "key1"

    def test_jwks_equality(self):
        """Test JWKS equality comparison."""
        keys1 = [{"kid": "key1", "kty": "RSA"}]
        keys2 = [{"kid": "key1", "kty": "RSA"}]
        keys3 = [{"kid": "key2", "kty": "RSA"}]

        jwks1 = JWKS(keys=keys1)
        jwks2 = JWKS(keys=keys2)
        jwks3 = JWKS(keys=keys3)

        assert jwks1 == jwks2
        assert jwks1 != jwks3

    def test_jwks_dict_conversion(self):
        """Test JWKS conversion to dictionary."""
        keys = [{"kid": "key1", "kty": "RSA", "alg": "RS256"}]
        jwks = JWKS(keys=keys)

        jwks_dict = jwks.model_dump()

        assert "keys" in jwks_dict
        assert jwks_dict["keys"] == keys

    def test_jwks_json_serialization(self):
        """Test JWKS JSON serialization."""
        keys = [{"kid": "key1", "kty": "RSA", "alg": "RS256"}]
        jwks = JWKS(keys=keys)

        jwks_json = jwks.model_dump_json()

        assert '"keys"' in jwks_json
        assert '"kid":"key1"' in jwks_json
        assert '"kty":"RSA"' in jwks_json

    def test_jwks_str_representation(self):
        """Test JWKS string representation."""
        keys = [{"kid": "key1", "kty": "RSA"}]
        jwks = JWKS(keys=keys)

        jwks_str = str(jwks)

        assert "keys" in jwks_str
        assert "key1" in jwks_str


class TestJWTAuthorizationCredentials:
    """Test cases for JWTAuthorizationCredentials class."""

    def test_jwt_credentials_creation_with_all_fields(self):
        """Test JWTAuthorizationCredentials creation with all fields."""
        credentials = JWTAuthorizationCredentials(
            jwt_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
            header={"typ": "JWT", "alg": "HS256"},
            claims={"sub": "1234567890", "name": "John Doe"},
            signature="signature_value",
            message="header.payload",
        )

        assert credentials.jwt_token.startswith("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9")
        assert credentials.header == {"typ": "JWT", "alg": "HS256"}
        assert credentials.claims == {"sub": "1234567890", "name": "John Doe"}
        assert credentials.signature == "signature_value"
        assert credentials.message == "header.payload"

    def test_jwt_credentials_creation_minimal_fields(self):
        """Test JWTAuthorizationCredentials creation with minimal required fields."""
        credentials = JWTAuthorizationCredentials(
            jwt_token="token", header={}, claims={}, signature="sig", message="msg"
        )

        assert credentials.jwt_token == "token"
        assert credentials.header == {}
        assert credentials.claims == {}
        assert credentials.signature == "sig"
        assert credentials.message == "msg"

    def test_jwt_credentials_header_validation(self):
        """Test JWTAuthorizationCredentials header field validation."""
        # Valid headers
        valid_headers = [
            {"typ": "JWT", "alg": "HS256"},
            {"typ": "JWT", "alg": "RS256", "kid": "key-1"},
            {"alg": "ES256"},
            {},  # Empty header should be valid
        ]

        for header in valid_headers:
            credentials = JWTAuthorizationCredentials(
                jwt_token="token",
                header=header,
                claims={},
                signature="sig",
                message="msg",
            )
            assert credentials.header == header

    def test_jwt_credentials_claims_validation(self):
        """Test JWTAuthorizationCredentials claims field validation."""
        # Various claim types
        claims_variants = [
            {"sub": "1234567890", "name": "John Doe", "admin": True},
            {"iss": "https://example.com", "aud": "api", "exp": 1234567890},
            {"custom_claim": "custom_value", "nested": {"key": "value"}},
            {},  # Empty claims should be valid
        ]

        for claims in claims_variants:
            credentials = JWTAuthorizationCredentials(
                jwt_token="token",
                header={"alg": "HS256"},
                claims=claims,
                signature="sig",
                message="msg",
            )
            assert credentials.claims == claims

    def test_jwt_credentials_with_cognito_claims(self):
        """Test JWTAuthorizationCredentials with AWS Cognito specific claims."""
        cognito_claims = {
            "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "aud": "xxxxxxxxxxxxxxxxxxxxxx",
            "cognito:groups": ["admin", "users"],
            "token_use": "access",
            "scope": "aws.cognito.signin.user.admin",
            "auth_time": 1234567890,
            "iss": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxxxxxx",
            "exp": 1234567890,
            "iat": 1234567890,
            "username": "johndoe",
        }

        credentials = JWTAuthorizationCredentials(
            jwt_token="cognito_token",
            header={"kid": "key-id", "alg": "RS256"},
            claims=cognito_claims,
            signature="cognito_signature",
            message="cognito_message",
        )

        assert credentials.claims["cognito:groups"] == ["admin", "users"]
        assert credentials.claims["token_use"] == "access"
        assert credentials.claims["username"] == "johndoe"

    def test_jwt_credentials_with_azure_claims(self):
        """Test JWTAuthorizationCredentials with Azure AD specific claims."""
        azure_claims = {
            "aud": "api://default",
            "iss": "https://sts.windows.net/tenant-id/",
            "iat": 1234567890,
            "nbf": 1234567890,
            "exp": 1234567890,
            "aio": "base64_encoded_value",
            "name": "John Doe",
            "oid": "object-id",
            "preferred_username": "john@company.com",
            "rh": "encoded_value",
            "roles": ["Admin", "User"],
            "scp": "User.Read",
            "sub": "subject-id",
            "tid": "tenant-id",
            "uti": "unique-token-id",
            "ver": "1.0",
        }

        credentials = JWTAuthorizationCredentials(
            jwt_token="azure_token",
            header={"typ": "JWT", "alg": "RS256", "kid": "azure-key-id"},
            claims=azure_claims,
            signature="azure_signature",
            message="azure_message",
        )

        assert credentials.claims["roles"] == ["Admin", "User"]
        assert credentials.claims["preferred_username"] == "john@company.com"
        assert credentials.claims["tid"] == "tenant-id"

    def test_jwt_credentials_equality(self):
        """Test JWTAuthorizationCredentials equality comparison."""
        creds1 = JWTAuthorizationCredentials(
            jwt_token="token1",
            header={"alg": "HS256"},
            claims={"sub": "123"},
            signature="sig1",
            message="msg1",
        )

        creds2 = JWTAuthorizationCredentials(
            jwt_token="token1",
            header={"alg": "HS256"},
            claims={"sub": "123"},
            signature="sig1",
            message="msg1",
        )

        creds3 = JWTAuthorizationCredentials(
            jwt_token="token2",
            header={"alg": "HS256"},
            claims={"sub": "123"},
            signature="sig1",
            message="msg1",
        )

        assert creds1 == creds2
        assert creds1 != creds3

    def test_jwt_credentials_dict_conversion(self):
        """Test JWTAuthorizationCredentials conversion to dictionary."""
        credentials = JWTAuthorizationCredentials(
            jwt_token="test_token",
            header={"alg": "HS256"},
            claims={"sub": "123", "name": "Test"},
            signature="test_signature",
            message="test_message",
        )

        creds_dict = credentials.model_dump()

        assert creds_dict["jwt_token"] == "test_token"
        assert creds_dict["header"] == {"alg": "HS256"}
        assert creds_dict["claims"] == {"sub": "123", "name": "Test"}
        assert creds_dict["signature"] == "test_signature"
        assert creds_dict["message"] == "test_message"

    def test_jwt_credentials_json_serialization(self):
        """Test JWTAuthorizationCredentials JSON serialization."""
        credentials = JWTAuthorizationCredentials(
            jwt_token="test_token",
            header={"alg": "HS256"},
            claims={"sub": "123"},
            signature="test_signature",
            message="test_message",
        )

        creds_json = credentials.model_dump_json()

        assert '"jwt_token":"test_token"' in creds_json
        assert '"alg":"HS256"' in creds_json
        assert '"sub":"123"' in creds_json

    def test_jwt_credentials_str_representation(self):
        """Test JWTAuthorizationCredentials string representation."""
        credentials = JWTAuthorizationCredentials(
            jwt_token="short_token",
            header={"alg": "HS256"},
            claims={"sub": "123"},
            signature="sig",
            message="msg",
        )

        creds_str = str(credentials)

        assert "short_token" in creds_str
        assert "HS256" in creds_str

    def test_jwt_credentials_with_long_token(self):
        """Test JWTAuthorizationCredentials with realistic long JWT token."""
        long_token = (
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IlJUVXhOVUZFTlRSRE9UYzVNVEkzUWpVek5ERkVP"
            "VFZGUWpnM1JrRTBRak5HUmpFNU1ERXhOZyJ9.eyJpc3MiOiJodHRwczovL2Rldi1leGFtcGxlLmF1dGgwLm"
            "NvbS8iLCJzdWIiOiJhdXRoMHw1ZTMzYjc2ZDI0MjYyMzBjNTY5MzYwMTEiLCJhdWQiOlsiaHR0cHM6Ly9h"
            "cGkuZXhhbXBsZS5jb20iLCJodHRwczovL2Rldi1leGFtcGxlLmF1dGgwLmNvbS91c2VyaW5mbyJdLCJpYX"
            "QiOjE1ODA3NDE4MjEsImV4cCI6MTU4MDc0OTAyMSwiYXpwIjoiWW91cjEyM0FwcElkIiwic2NvcGUiOiJv"
            "cGVuaWQgcHJvZmlsZSBlbWFpbCJ9.signature_would_be_here_in_real_jwt"
        )

        credentials = JWTAuthorizationCredentials(
            jwt_token=long_token,
            header={"alg": "RS256", "typ": "JWT", "kid": "key-id"},
            claims={
                "iss": "https://dev-example.auth0.com/",
                "sub": "auth0|5e33b76d2426230c56936011",
                "aud": [
                    "https://api.example.com",
                    "https://dev-example.auth0.com/userinfo",
                ],
                "iat": 1580741821,
                "exp": 1580749021,
                "azp": "Your123AppId",
                "scope": "openid profile email",
            },
            signature="signature_would_be_here_in_real_jwt",
            message="header.payload",
        )

        assert credentials.jwt_token == long_token
        assert credentials.header["alg"] == "RS256"
        assert credentials.claims["iss"] == "https://dev-example.auth0.com/"

    def test_jwt_credentials_immutability(self):
        """Test that JWTAuthorizationCredentials fields maintain their values."""
        original_header = {"alg": "HS256", "typ": "JWT"}
        original_claims = {"sub": "123", "name": "Test"}

        credentials = JWTAuthorizationCredentials(
            jwt_token="test_token",
            header=original_header,
            claims=original_claims,
            signature="test_signature",
            message="test_message",
        )

        # Modify original dictionaries
        original_header["kid"] = "new-key-id"
        original_claims["admin"] = True

        # Credentials should maintain original values
        assert "kid" not in credentials.header
        assert "admin" not in credentials.claims
        assert credentials.header == {"alg": "HS256", "typ": "JWT"}
        assert credentials.claims == {"sub": "123", "name": "Test"}


class TestJWTTypesIntegration:
    """Integration tests for JWT types."""

    def test_jwks_and_jwt_credentials_together(self):
        """Test JWKS and JWTAuthorizationCredentials working together."""
        # Simulate fetching JWKS
        jwks_keys = [
            {"kid": "key-1", "kty": "RSA", "alg": "RS256"},
            {"kid": "key-2", "kty": "RSA", "alg": "RS256"},
        ]
        jwks = JWKS(keys=jwks_keys)

        # Simulate JWT token using one of the keys
        credentials = JWTAuthorizationCredentials(
            jwt_token="jwt_token_here",
            header={"alg": "RS256", "typ": "JWT", "kid": "key-1"},
            claims={"sub": "user123", "iss": "https://issuer.com"},
            signature="signature_here",
            message="header.payload",
        )

        # Find matching key
        token_kid = credentials.header.get("kid")
        matching_key = next(
            (key for key in jwks.keys if key.get("kid") == token_kid), None
        )

        assert matching_key is not None
        assert matching_key["kid"] == "key-1"
        assert matching_key["alg"] == "RS256"

    def test_complex_jwt_workflow(self):
        """Test complex JWT validation workflow simulation."""
        # Step 1: Create JWKS with multiple keys
        jwks = JWKS(
            keys=[
                {"kid": "rsa-key-1", "kty": "RSA", "alg": "RS256", "use": "sig"},
                {"kid": "rsa-key-2", "kty": "RSA", "alg": "RS256", "use": "sig"},
                {"kid": "ec-key-1", "kty": "EC", "alg": "ES256", "use": "sig"},
            ]
        )

        # Step 2: Create JWT credentials
        jwt_creds = JWTAuthorizationCredentials(
            jwt_token="eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS1rZXktMSJ9...",
            header={"alg": "RS256", "typ": "JWT", "kid": "rsa-key-1"},
            claims={
                "sub": "user123",
                "iss": "https://auth.example.com",
                "aud": "api.example.com",
                "exp": 9999999999,
                "iat": 1234567890,
                "scope": "read write",
                "roles": ["user", "admin"],
            },
            signature="signature_value",
            message="header.claims",
        )

        # Step 3: Simulate key lookup
        header_kid = jwt_creds.header.get("kid")
        public_key = next(
            (key for key in jwks.keys if key.get("kid") == header_kid), None
        )

        # Step 4: Verify workflow
        assert public_key is not None
        assert public_key["kty"] == "RSA"
        assert jwt_creds.claims["sub"] == "user123"
        assert "admin" in jwt_creds.claims["roles"]

        # Step 5: Simulate token validation results
        is_signature_valid = (
            public_key["alg"] == jwt_creds.header["alg"]
        )  # Simplified check
        is_not_expired = jwt_creds.claims["exp"] > 1234567890
        has_required_audience = jwt_creds.claims["aud"] == "api.example.com"

        assert is_signature_valid
        assert is_not_expired
        assert has_required_audience
