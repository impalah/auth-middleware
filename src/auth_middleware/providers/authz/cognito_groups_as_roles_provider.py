from typing import Any

from auth_middleware.providers.cognito import COGNITO_GROUPS_CLAIM
from auth_middleware.providers.authz.roles_provider import RolesProvider
from auth_middleware.types.jwt import JWTAuthorizationCredentials


class CognitoGroupsAsRolesProvider(RolesProvider):
    """Recovers groups from AWS Cognito using the token provided

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

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
            if isinstance(token, JWTAuthorizationCredentials) and (COGNITO_GROUPS_CLAIM in token.claims or "scope" in token.claims)
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

        # cognito:groups is a list of groups
        # scope is only ONE scope

        return (
            claims[COGNITO_GROUPS_CLAIM]
            if COGNITO_GROUPS_CLAIM in claims
            else [str(claims["scope"]).split("/")[-1]]
        )
