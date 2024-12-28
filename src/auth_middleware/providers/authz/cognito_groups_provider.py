from typing import Optional, List


from auth_middleware.types.jwt import JWTAuthorizationCredentials
from auth_middleware.logging import logger
from auth_middleware.providers.authz.groups_provider import GroupsProvider


class CognitoGroupsProvider(GroupsProvider):
    """Recovers groups from AWS Cognito using the token provided

    Args:
        metaclass (_type_, optional): _description_. Defaults to ABCMeta.
    """

    async def fetch_groups(self, token: JWTAuthorizationCredentials) -> List[str]:
        """Get groups using the token provided

        Args:
            token (JWTAuthorizationCredentials): _description_

        Raises:
            NotImplementedError: _description_

        Returns:
            List[str]: _description_
        """

        groups: List[str] = (
            self.__get_groups_from_claims(token.claims)
            if "cognito:groups" in token.claims or "scope" in token.claims
            else []
        )

        return groups

    def __get_groups_from_claims(self, claims: dict) -> List[str]:
        """Extracts groups from claims.

        Args:
            claims (dict): JWT claims.

        Returns:
            List[str]: List of groups.
        """

        # cognito:groups is a list of groups
        # scope is only ONE scope

        return (
            claims["cognito:groups"]
            if "cognito:groups" in claims
            else [str(claims["scope"]).split("/")[-1]]
        )
