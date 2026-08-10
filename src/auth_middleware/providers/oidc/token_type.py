"""OAuth2/OIDC token type classification."""

from enum import Enum


class TokenType(str, Enum):
    """The kind of token a Bearer credential turned out to be.

    Identity providers don't agree on how (or whether) they label this:
    Cognito sets an explicit ``token_use`` claim; most standards-compliant
    OIDC providers (Authentik, Keycloak, Auth0, ...) don't, so it has to be
    inferred from which claims are present instead. See
    :meth:`~auth_middleware.providers.oidc.oidc_provider.OidcProvider._detect_token_type`.
    """

    ID = "id"
    ACCESS = "access"
    REFRESH = "refresh"
    UNKNOWN = "unknown"
