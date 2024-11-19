from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field

from auth_middleware.providers.authz.groups_provider import GroupsProvider
from auth_middleware.providers.authz.permissions_provider import PermissionsProvider

JWK = Dict[str, str]


class JWKS(BaseModel):
    keys: Optional[List[JWK]] = []
    timestamp: Optional[int] = None
    usage_counter: Optional[int] = 0


class JWTAuthorizationCredentials(BaseModel):
    jwt_token: str
    header: Dict[str, str]
    claims: Dict[str, Any]
    signature: str
    message: str


class User(BaseModel):
    """Application User

    Args:
        BaseModel (BaseModel): Inherited properties
    """

    class Config:
        arbitrary_types_allowed = True

    def __init__(
        self,
        permissions_provider: GroupsProvider = None,
        groups_provider: PermissionsProvider = None,
        **data: Any,
    ):

        super().__init__(**data)

        # Store the permissions provider (e.g., SQL, DynamoDB, etc.)
        self.permissions_provider = permissions_provider

        # Store the groups provider (e.g., SQL, DynamoDB, etc.)
        self.groups_provider = groups_provider

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

    groups: Optional[List[str]] = Field(
        default=[],
        json_schema_extra={
            "description": "List of user groups",
            "example": '["admin", "user"]',
        },
    )


class UserCredentials(User):
    """User object with credentials included

    Args:
        User (_type_): _description_
    """

    hashed_password: str = Field(
        ...,
        max_length=500,
        json_schema_extra={
            "description": "Hashed password",
            "example": "0ujsswThIGTUYm2K8FjOOfXtY1K",
        },
    )
