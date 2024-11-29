import os
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import Response
from uvicorn import run

from pydantic import BaseModel, EmailStr, Field, PrivateAttr
from typing import Any, Dict, List

from auth_middleware.functions import has_permissions, require_permissions
from auth_middleware.types.user import User
from auth_middleware import (
    JwtAuthMiddleware,
    get_current_user,
    require_groups,
    require_user,
)
from auth_middleware.providers.authz.cognito_groups_provider import (
    CognitoGroupsProvider,
)
from auth_middleware.providers.authz.sql_groups_provider import SqlGroupsProvider
from auth_middleware.providers.authz.sql_permissions_provider import (
    SqlPermissionsProvider,
)
from auth_middleware.providers.authn.cognito_provider import (
    CognitoProvider,
)


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

app: FastAPI = FastAPI()
app.add_middleware(
    JwtAuthMiddleware,
    auth_provider=CognitoProvider(
        groups_provider=CognitoGroupsProvider(),
        permissions_provider=SqlPermissionsProvider(),
    ),
)


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

    # Get variables from environment
    cognito_domain: str = os.getenv("COGNITO_DOMAIN")
    cognito_client_id: str = os.getenv("COGNITO_CLIENT_ID")
    region: str = os.getenv("AWS_REGION")

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "Testing FastAPI with Cognito",
            "message": "Testing FastAPI with Cognito",
            "cognito_domain": cognito_domain,
            "region": region,
            "cognito_client_id": cognito_client_id,
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
