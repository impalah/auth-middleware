from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field

from auth_middleware.types.user import User


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
