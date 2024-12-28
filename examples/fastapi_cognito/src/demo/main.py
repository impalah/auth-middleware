import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, status
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr, Field, PrivateAttr
from settings import settings
from starlette.requests import Request
from starlette.responses import Response
from uvicorn import run

from auth_middleware import (
    JwtAuthMiddleware,
    get_current_user,
    require_groups,
    require_user,
)
from auth_middleware.functions import has_permissions, require_permissions
from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.cognito_provider import CognitoProvider
from auth_middleware.providers.authz.async_database import AsyncDatabase
from auth_middleware.providers.authz.cognito_groups_provider import (
    CognitoGroupsProvider,
)
from auth_middleware.providers.authz.sql_groups_provider import SqlGroupsProvider
from auth_middleware.providers.authz.sql_permissions_provider import (
    SqlPermissionsProvider,
)
from auth_middleware.types.user import User


def init_database():
    """Initialize the database connection"""

    # Get parameters manually
    AsyncDatabase.initialize(
        settings.SQLALCHEMY_DATABASE_URI,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_recycle=3600,
        echo=True,
        pool_timeout=30,
    )


def custom_openapi(app: FastAPI):
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Auth Middleware Test API",
        version="0.1.0",
        description="API for testing authentication middleware",
        routes=app.routes,
    )

    # Define security schema
    openapi_schema["components"]["securitySchemes"] = {
        "bearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }

    # Apply security schema globally
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method["security"] = [{"bearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


# class UserResponse(BaseModel):
#     """Application User

#     Args:
#         BaseModel (BaseModel): Inherited properties
#     """

#     id: str = Field(
#         ...,
#         max_length=500,
#         json_schema_extra={
#             "description": "Unique user ID (sub)",
#             "example": "0ujsswThIGTUYm2K8FjOOfXtY1K",
#         },
#     )

#     name: Optional[str] = Field(
#         default=None,
#         max_length=500,
#         json_schema_extra={
#             "description": "User name",
#             "example": "test_user",
#         },
#     )

#     email: Optional[EmailStr] = Field(
#         default=None,
#         max_length=500,
#         json_schema_extra={
#             "description": "User's email address (Optional)",
#             "example": "useradmin@user.com",
#         },
#     )

#     groups: Optional[List[str]] = Field(
#         default=[],
#         json_schema_extra={
#             "description": "List of user groups",
#             "example": '["admin", "user"]',
#         },
#     )


base_dir = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=base_dir.joinpath("..", "..", "templates"))

# Initialize database manually
init_database()

# Initialize settings (read from .env file)
provider_settings: CognitoAuthzProviderSettings = CognitoAuthzProviderSettings(
    user_pool_id=settings.USER_POOL_ID,
    user_pool_region=settings.AWS_REGION,
    jwt_token_verification_disabled=settings.TOKEN_VERIFICATION_DISABLED,
)


app: FastAPI = FastAPI()
app.add_middleware(
    JwtAuthMiddleware,
    auth_provider=CognitoProvider(
        settings=provider_settings,
        groups_provider=CognitoGroupsProvider,
        # permissions_provider=SqlPermissionsProvider,
    ),
)

app.openapi = lambda: custom_openapi(app)


def get_stranger_message(request: Request) -> JSONResponse:
    """Get a message for a stranger (auth disabled)

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Hello stranger (auth disabled)"},
    )


@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request, access_token: Optional[str] = None, id_token: Optional[str] = None
) -> HTMLResponse:

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "Testing FastAPI with Cognito",
            "message": "Testing FastAPI with Cognito",
            "cognito_domain": settings.USER_POOL_DOMAIN,
            "region": settings.AWS_REGION,
            "cognito_client_id": settings.USER_POOL_CLIENT_ID,
            "access_token": access_token,
            "id_token": id_token,
        },
    )


# @app.get(
#     "/user",
#     dependencies=[
#         Depends(require_user()),
#     ],
#     response_class=UserResponse,
#     status_code=status.HTTP_200_OK,
# )
# async def get_user(
#     request: Request, current_user: User = Depends(get_current_user())
# ) -> UserResponse:
#     """Returns full user information

#     Args:
#         request (Request): FastAPI request object

#     Returns:
#         JSONResponse: a message
#     """

#     # return JSONResponse(
#     #     status_code=status.HTTP_200_OK,
#     #     content={"message": "Everything is fine"},
#     # )

#     response = UserResponse(
#         id="0ujsswThIGTUYm2K8FjOOfXtY1K",
#         name="my name",
#         email="mail@mail.com",
#         groups=["group1"],
#     )

#     return response


@app.get(
    "/gimme/user",
    dependencies=[
        Depends(require_user()),
    ],
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def root(
    request: Request, current_user: User = Depends(get_current_user())
) -> JSONResponse:
    """A simple call with user authorization required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """

    if current_user is None:
        return get_stranger_message(request)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "id": current_user.id,
            "name": current_user.name,
            "email": current_user.email,
            "groups": await current_user.groups,
            "permissions": await current_user.permissions,
        },
    )


@app.get(
    "/healthcheck",
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def root(request: Request) -> JSONResponse:
    """A simple call with no authorization required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: just a message
    """

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "Everything is fine"},
    )


@app.get(
    "/hello/user",
    dependencies=[
        Depends(require_user()),
    ],
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def hello_user(
    request: Request, current_user: User = Depends(get_current_user())
) -> JSONResponse:
    """A simple call with user authorization required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """

    if current_user is None:
        return get_stranger_message(request)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"Hello dear {current_user.name}"},
    )


@app.get(
    "/hello/groups/admin",
    dependencies=[
        Depends(require_groups(["administrator"])),
    ],
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def require_admin(request: Request) -> JSONResponse:
    """A simple call with admin authorization required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"Hello dear admin {request.state.current_user.name}"},
    )


@app.get(
    "/hello/permissions/admin",
    dependencies=[
        Depends(require_permissions(["hello.admin"])),
    ],
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def require_permission_admin(request: Request) -> JSONResponse:
    """A simple call with admin permission required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"Hello dear admin {request.state.current_user.name}"},
    )


@app.get(
    "/hello/has-permissions/admin",
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def has_permission_admin(request: Request) -> JSONResponse:
    """A simple call with admin permission required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """

    if not await has_permissions(request, ["hello.admin"]):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "message": f"Hello dear {request.state.current_user.name}, you do not have the required permissions"
            },
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"Hello dear admin {request.state.current_user.name}"},
    )


if __name__ == "__main__":

    # Be careful!!! This call does not read the .env file
    run(app, host="0.0.0.0", port=8000)
