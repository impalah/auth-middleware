from pydantic import Field

from auth_middleware.providers.aws.jwt_provider_settings import JWTProviderSettings


class OidcProviderSettings(JWTProviderSettings):
    """Settings for a generic OpenID Connect provider.

    Works with any standards-compliant OIDC identity provider (Authentik,
    Keycloak, Auth0, Okta, ...): the JWKS is discovered from the issuer's
    ``.well-known/openid-configuration`` document unless ``jwks_uri`` is
    set explicitly.
    """

    issuer: str = Field(
        description=(
            "OIDC issuer URL, e.g. https://authentik.example.com/application/o/my-app/"
        ),
    )

    audience: str | None = Field(
        default=None,
        description=(
            "Expected 'aud' claim (the OIDC client ID). Strongly "
            "recommended: without it, any token signed by the issuer for "
            "any client is accepted."
        ),
    )

    jwks_uri: str | None = Field(
        default=None,
        description=(
            "Explicit JWKS URL. If not set, it is discovered from "
            "'{issuer}/.well-known/openid-configuration' on first use."
        ),
    )

    discovery_url: str | None = Field(
        default=None,
        description=(
            "Override for the OIDC discovery document URL. Defaults to "
            "'{issuer}/.well-known/openid-configuration'."
        ),
    )

    algorithms: list[str] = Field(
        default_factory=lambda: ["RS256"],
        description="JWS algorithms accepted when verifying the token signature",
    )

    username_claim: str = Field(
        default="preferred_username",
        description="Claim used as the user's display name",
    )

    groups_claim: str | None = Field(
        default="groups",
        description=(
            "Claim containing the user's groups, if present in the token. "
            "Set to None to disable extracting groups from the token claims "
            "(e.g. when using a separate GroupsProvider instead)."
        ),
    )

    jwks_cache_interval: int | None = Field(
        default=20,
        description="Cache interval refresh time (minutes)",
    )

    jwks_cache_usages: int | None = Field(
        default=1000,
        description="Number of jwks signature verifications before refresh",
    )
