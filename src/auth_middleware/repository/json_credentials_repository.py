import json
import os

from auth_middleware.logging import logger
from auth_middleware.repository.credentials_repository import CredentialsRepository
from auth_middleware.repository.settings import settings
from auth_middleware.types.user_credentials import UserCredentials


class JsonCredentialsRepository(CredentialsRepository):
    """Repository for managing users with JSON files

    Args:
        AuthRepository (_type_): _description_
    """

    def __init__(self, *args, **kwargs):
        """Repository initialization"""

        # Open the credentials file
        current_path = os.getcwd()
        file_path = os.path.join(
            current_path, settings.AUTH_MIDDLEWARE_JSON_REPOSITORY_PATH
        )

        logger.debug("Opening credentials file: {}", file_path)

        # TODO: Control exceptions
        with open(file_path) as f:
            self._database = json.load(f)

    async def get_by_id(self, *, id: str) -> UserCredentials | None:
        """Get user by id from the database

        Args:
            id (str): _description_

        Returns:
            Optional[User]: _description_
        """

        if id not in self._database:
            return None

        user_data = self._database[id]

        return UserCredentials(
            id=id,
            name=user_data["name"],
            hashed_password=user_data["hashed_pwd"],
            groups=user_data["groups"] if "groups" in user_data else [],
            email=user_data["email"] if "email" in user_data else None,
        )
