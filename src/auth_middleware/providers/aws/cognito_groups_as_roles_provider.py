from typing import Any

from auth_middleware.contracts.roles_provider import RolesProvider
from auth_middleware.providers.aws import COGNITO_GROUPS_CLAIM
from auth_middleware.types.jwt import JWTAuthorizationCredentials


class CognitoGroupsAsRolesProvider(RolesProvider):
    """Recovers groups from AWS Cognito, exposed as roles, using the token
    provided.

    Args:
        groups_claim (str): name of the claim carrying the user's groups
            (a list of group names on ID tokens). Defaults to
            ``COGNITO_GROUPS_CLAIM`` (``"cognito:groups"``).
    """

    def __init__(self, *, groups_claim: str = COGNITO_GROUPS_CLAIM) -> None:
        self._groups_claim = groups_claim

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

        # 'scope' is a space-separated list of OAuth2 scopes. Only a
        # single custom scope in the Cognito 'resourceServer/scopeName'
        # format can be mapped to one role name; a real user access
        # token's standard multi-scope claim (e.g. "openid profile
        # email") carries no role information and must not be
        # misread as a single role.
        scopes = str(claims["scope"]).split()
        if len(scopes) != 1:
            return []
        return [scopes[0].split("/")[-1]]
