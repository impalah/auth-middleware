from typing import Optional, List


from auth_middleware.jwt import JWTAuthorizationCredentials
from auth_middleware.logging import logger
from auth_middleware.providers.authz.groups_provider import GroupsProvider


class SqlGroupsProvider(GroupsProvider):
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

        return ["admin", "user"]
