from collections.abc import Mapping
from typing import Any

from auth_middleware.contracts.roles_provider import RolesProvider
from auth_middleware.providers.aws import COGNITO_GROUPS_CLAIM
from auth_middleware.providers.aws.scope_mapping import names_from_scope
from auth_middleware.types.jwt import JWTAuthorizationCredentials


class CognitoGroupsAsRolesProvider(RolesProvider):
    """Recovers groups from AWS Cognito, exposed as roles, using the token
    provided.

    Args:
        groups_claim (str): name of the claim carrying the user's groups
            (a list of group names on ID tokens). Defaults to
            ``COGNITO_GROUPS_CLAIM`` (``"cognito:groups"``).
        resource_server (str | None): identifier of your Cognito resource
            server. Machine tokens carry no groups claim, only a custom scope
            ``"<resource_server>/<name>"``; when set, such a single scope maps
            to ``<name>``. Scopes of other resource servers never map.
        scope_map (Mapping[str, str] | None): exact ``full scope -> name``
            table, an alternative (or addition) to ``resource_server``.

    Without ``resource_server`` or ``scope_map`` the ``scope`` claim is ignored
    (fail closed): blindly stripping the prefix would turn a token issued for
    another resource server into one of your groups.
    """

    def __init__(
        self,
        *,
        groups_claim: str = COGNITO_GROUPS_CLAIM,
        resource_server: str | None = None,
        scope_map: Mapping[str, str] | None = None,
    ) -> None:
        self._groups_claim = groups_claim
        self._resource_server = resource_server
        self._scope_map = dict(scope_map) if scope_map else None

    async def fetch_roles(self, token: str | JWTAuthorizationCredentials) -> list[str]:
        """Get roles using the token provided

        Args:
            token (JWTAuthorizationCredentials | str): The token containing the claims.

        Raises:
            NotImplementedError: _description_

        Returns:
            List[str]: _description_
        """

        groups: list[str] = (
            self.__get_groups_from_claims(token.claims)
            if isinstance(token, JWTAuthorizationCredentials)
            and (self._groups_claim in token.claims or "scope" in token.claims)
            else []
        )

        return groups

    def __get_groups_from_claims(self, claims: dict[str, Any]) -> list[str]:
        """Extracts groups from claims.

        Args:
            claims (dict): JWT claims.

        Returns:
            List[str]: List of groups.
        """

        if self._groups_claim in claims:
            # the groups claim is a list of groups
            return list(claims[self._groups_claim])

        return names_from_scope(
            claims,
            resource_server=self._resource_server,
            scope_map=self._scope_map,
        )
