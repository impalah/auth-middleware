from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, PrivateAttr

from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
import asyncio


class User(BaseModel):
    """Application User

    Args:
        BaseModel (BaseModel): Inherited properties
    """

    class Config:
        arbitrary_types_allowed = True

    _permissions_provider: Optional[PermissionsProvider] = PrivateAttr()
    _groups_provider: Optional[GroupsProvider] = PrivateAttr()
    _token: Optional[str] = PrivateAttr()

    _groups: Optional[List[str]] = None
    _groups_task: Optional[asyncio.Task] = None
    _permissions: Optional[List[str]] = None
    _permissions_task: Optional[asyncio.Task] = None

    def __init__(
        self,
        token: str = None,
        permissions_provider: GroupsProvider = None,
        groups_provider: PermissionsProvider = None,
        **data: Any,
    ):

        super().__init__(**data)

        # Store the token
        self._token = token

        # Store the permissions provider (e.g., SQL, DynamoDB, etc.)
        self._permissions_provider = permissions_provider

        # Store the groups provider (e.g., SQL, DynamoDB, etc.)
        self._groups_provider = groups_provider

    id: str = Field(
        ...,
        max_length=500,
        json_schema_extra={
            "description": "Unique user ID (sub)",
            "example": "0ujsswThIGTUYm2K8FjOOfXtY1K",
        },
    )

    name: Optional[str] = Field(
        default=None,
        max_length=500,
        json_schema_extra={
            "description": "User name",
            "example": "test_user",
        },
    )

    email: Optional[EmailStr] = Field(
        default=None,
        max_length=500,
        json_schema_extra={
            "description": "User's email address (Optional)",
            "example": "useradmin@user.com",
        },
    )

    # groups: Optional[List[str]] = Field(
    #     default=[],
    #     json_schema_extra={
    #         "description": "List of user groups",
    #         "example": '["admin", "user"]',
    #     },
    # )

    # @property
    # def groups(self) -> List[str]:
    #     """Lazy loads the groups from the given provider

    #     Returns:
    #         List[str]: List of groups for the user
    #     """
    #     if not self._groups_provider or not self._token:
    #         return []

    #     cache_key = f"user:{self.id}:groups"

    #     # If not in cache, fetch from the database using the injected provider
    #     groups = await self._groups_provider.fetch_groups(self._token)

    #     return groups

    @property
    async def groups(self) -> List[str]:
        """Async property to get the groups of the user.

        Returns:
            List[str]: _description_
        """
        if self._groups is None:
            if self._groups_task is None:
                # Init a new async task to load the groups
                self._groups_task = asyncio.create_task(self._load_groups())

            # Wait for the task to finish
            self._groups = await self._groups_task

        return self._groups

    async def _load_groups(self) -> List[str]:
        """Load the groups of the user.

        Returns:
            List[str]: _description_
        """
        if not self._groups_provider or not self._token:
            return []

        groups = await self._groups_provider.fetch_groups(self._token)
        return groups

    @property
    async def permissions(self) -> List[str]:
        """Async property to get the permissions of the user.

        Returns:
            List[str]: _description_
        """
        if self._permissions is None:
            if self._permissions_task is None:
                # Init a new async task to load the groups
                self._permissions_task = asyncio.create_task(self._load_permissions())

            # Wait for the task to finish
            self._permissions = await self._permissions_task

        return self._permissions

    async def _load_permissions(self) -> List[str]:
        """Load the permissions of the user.

        Returns:
            List[str]: _description_
        """
        if not self._permissions_provider or not self._token:
            return []

        permissions = await self._permissions_provider.fetch_permissions(self._token)
        return permissions
