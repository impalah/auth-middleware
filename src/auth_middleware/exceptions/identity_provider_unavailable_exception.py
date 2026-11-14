from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException


class IdentityProviderUnavailableException(InvalidTokenException):
    """The identity provider (JWKS/discovery) is unreachable or answered nonsense.

    It is an outage, not a bad token: the middleware answers ``503`` instead of
    ``401``, so valid users are not told their credentials are wrong. It subclasses
    :class:`InvalidTokenException` so existing ``except`` clauses keep working.
    """
