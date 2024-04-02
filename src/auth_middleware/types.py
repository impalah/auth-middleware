from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field

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
