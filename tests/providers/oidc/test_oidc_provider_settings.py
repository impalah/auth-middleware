"""Tests for OidcProviderSettings."""

import pytest
from pydantic import ValidationError

from auth_middleware.providers.oidc.oidc_provider_settings import OidcProviderSettings


class TestOidcProviderSettings:
    def test_requires_issuer(self):
        with pytest.raises(ValidationError):
            OidcProviderSettings()

    def test_default_values(self):
        settings = OidcProviderSettings(issuer="https://idp.example.com/app/")

        assert settings.issuer == "https://idp.example.com/app/"
        assert settings.audience is None
        assert settings.jwks_uri is None
        assert settings.discovery_url is None
        assert settings.algorithms == ["RS256"]
        assert settings.username_claim == "preferred_username"
        assert settings.groups_claim == "groups"
        assert settings.jwks_cache_interval == 20
        assert settings.jwks_cache_usages == 1000
        assert settings.jwt_leeway == 0

    def test_explicit_values(self):
        settings = OidcProviderSettings(
            issuer="https://idp.example.com/app/",
            audience="my-client-id",
            jwks_uri="https://idp.example.com/app/jwks/",
            discovery_url="https://idp.example.com/custom-discovery",
            algorithms=["RS256", "ES256"],
            username_claim="upn",
            groups_claim=None,
            jwt_leeway=30,
        )

        assert settings.audience == "my-client-id"
        assert settings.jwks_uri == "https://idp.example.com/app/jwks/"
        assert settings.discovery_url == "https://idp.example.com/custom-discovery"
        assert settings.algorithms == ["RS256", "ES256"]
        assert settings.username_claim == "upn"
        assert settings.groups_claim is None
        assert settings.jwt_leeway == 30
