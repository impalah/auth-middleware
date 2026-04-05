import asyncio
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, PrivateAttr

if TYPE_CHECKING:
    from auth_middleware.providers.authz.groups_provider import GroupsProvider
    from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
    from auth_middleware.providers.profile.profile_provider import ProfileProvider
    from auth_middleware.types.jwt import JWTAuthorizationCredentials


class User(BaseModel):
    """Application User

    Args:
        BaseModel (BaseModel): Inherited properties
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    _permissions_provider: PermissionsProvider | None = PrivateAttr(default=None)
    _groups_provider: GroupsProvider | None = PrivateAttr(default=None)
    _profile_provider: ProfileProvider | None = PrivateAttr(default=None)
    _token: str | None = PrivateAttr(default=None)
    _jwt_credentials: JWTAuthorizationCredentials | None = PrivateAttr(default=None)

    _groups: list[str] | None = None
    _groups_task: asyncio.Task[list[str]] | None = None
    _permissions: list[str] | None = None
    _permissions_task: asyncio.Task[list[str]] | None = None
    _profile: dict[str, Any] | None = None
    _profile_task: asyncio.Task[dict[str, Any]] | None = None

    def __init__(
        self,
        token: str | None = None,
        jwt_credentials: JWTAuthorizationCredentials | None = None,
        permissions_provider: PermissionsProvider | None = None,
        groups_provider: GroupsProvider | None = None,
        profile_provider: ProfileProvider | None = None,
        **data: Any,
    ):
        super().__init__(**data)

        # Store the token
        self._token = token

        # Store JWT credentials for M2M detection
        self._jwt_credentials = jwt_credentials

        # Store the permissions provider (e.g., SQL, DynamoDB, etc.)
        self._permissions_provider = permissions_provider

        # Store the groups provider (e.g., SQL, DynamoDB, etc.)
        self._groups_provider = groups_provider

        # Store the profile provider (e.g., Cognito, SQL, etc.)
        self._profile_provider = profile_provider

        # Handle groups passed directly in constructor
        if "groups" in data:
            self._groups = data["groups"]

    id: str = Field(
        ...,
        max_length=500,
        json_schema_extra={
            "description": "Unique user ID (sub)",
            "example": "0ujsswThIGTUYm2K8FjOOfXtY1K",
        },
    )

    name: str | None = Field(
        default=None,
        max_length=500,
        json_schema_extra={
            "description": "User name",
            "example": "test_user",
        },
    )

    email: EmailStr | None = Field(
        default=None,
        max_length=500,
        json_schema_extra={
            "description": "User's email address (Optional)",
            "example": "useradmin@user.com",
        },
    )

    is_m2m: bool = Field(
        default=False,
        json_schema_extra={
            "description": "Whether this is a Machine-to-Machine (M2M) authentication",
            "example": False,
        },
    )

    client_id: str | None = Field(
        default=None,
        max_length=500,
        json_schema_extra={
            "description": "Client ID for M2M authentication (None for user tokens)",
            "example": "7a8b9c0d1e2f3g4h5i6j",
        },
    )

    # groups: Optional[List[str]] = Field(
    #     default=None,
    #     json_schema_extra={
    #         "description": "List of user groups",
    #         "example": '["admin", "user"]',
    #     },
    # )

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
    async def groups(self) -> list[str]:
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

    async def _load_groups(self) -> list[str]:
        """Load the groups of the user.

        Returns:
            List[str]: _description_
        """
        # If groups were set directly in constructor, return them
        if self._groups is not None:
            return self._groups

        if not self._groups_provider or not self._token:
            return []

        groups = await self._groups_provider.fetch_groups(self._token)
        return groups

    @property
    async def permissions(self) -> list[str]:
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

    async def _load_permissions(self) -> list[str]:
        """Load the permissions of the user.

        Returns:
            List[str]: _description_
        """
        if not self._permissions_provider or not self._token:
            return []

        permissions = await self._permissions_provider.fetch_permissions(self._token)
        return permissions

    @property
    async def profile(self) -> dict[str, Any]:
        """Async property to get the profile attributes of the user.

        Returns the arbitrary key-value dict provided by the configured
        ``ProfileProvider``. Returns an empty dict when no provider is set or
        the user has no profile.

        Returns:
            dict[str, Any]: Profile attributes.
        """
        if self._profile is None:
            if self._profile_task is None:
                self._profile_task = asyncio.create_task(self._load_profile())
            self._profile = await self._profile_task

        return self._profile

    async def _load_profile(self) -> dict[str, Any]:
        """Load the profile attributes of the user."""
        if not self._profile_provider:
            return {}

        return await self._profile_provider.fetch_profile(self.id)
