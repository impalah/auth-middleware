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

    username_claim_fallbacks: list[str] = Field(
        default_factory=list,
        description=(
            "Additional claims tried, in order, if 'username_claim' is "
            "absent from the token. Useful for issuers whose ID and access "
            "tokens carry the display name under different claims (e.g. "
            "Cognito: 'username' on access tokens, 'cognito:username' on ID "
            "tokens)."
        ),
    )

    groups_claim: str | None = Field(
        default="groups",
        description=(
            "Claim containing the user's groups, if present in the token. "
            "Used as a fallback only when OidcProvider is constructed "
            "without a GroupsProvider (or for machine-to-machine tokens, "
            "which never consult a GroupsProvider) — an explicitly "
            "configured GroupsProvider always takes precedence over this "
            "claim. Set to None to disable extracting groups from the "
            "token claims entirely."
        ),
    )

    token_use_claim: str | None = Field(
        default="token_use",
        description=(
            "Claim carrying an explicit token type marker, as Cognito sets "
            "it (values 'id'/'access'/'refresh'). Most generic OIDC "
            "providers (Authentik, Keycloak, ...) don't set this, in which "
            "case the token type falls back to the identity_claims/"
            "client_id_claims heuristic below. Set to None to always use "
            "the heuristic, even for issuers that happen to set this claim."
        ),
    )

    identity_claims: list[str] = Field(
        default_factory=lambda: ["email", "name", "username"],
        description=(
            "Claims whose presence indicates a token represents a real "
            "user rather than a service/client (used, together with "
            "username_claim, as the id/access token-type heuristic and for "
            "machine-to-machine detection when token_use_claim is absent "
            "or not set on the token). Includes 'username' by default so "
            "Cognito *access* tokens - which carry 'username' but not "
            "'preferred_username'/'email' - aren't misclassified as "
            "machine-to-machine."
        ),
    )

    client_id_claims: list[str] = Field(
        default_factory=lambda: ["client_id", "azp"],
        description=(
            "Claims that identify the OAuth client a token was issued to. "
            "Used as a fallback audience check for access tokens that "
            "carry no 'aud' claim at all (e.g. Cognito access tokens use "
            "'client_id' instead), and to detect machine-to-machine "
            "tokens and populate User.client_id."
        ),
    )

    detect_m2m_tokens: bool = Field(
        default=True,
        description=(
            "Whether to detect machine-to-machine (client_credentials) "
            "tokens heuristically and skip groups/roles-provider lookups "
            "for them. Disable if it misclassifies your provider's tokens."
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
