import os
from typing import Optional

from fastapi import Depends, FastAPI, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import Response
from uvicorn import run

from auth_middleware.functions import require_groups, require_user
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
from auth_middleware.providers.entra_id import (
    EntraIDProvider,
    get_login_url,
    get_logout_url,
)

templates = Jinja2Templates(directory="templates")

app: FastAPI = FastAPI()
app.add_middleware(JwtAuthMiddleware, auth_provider=EntraIDProvider())


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
    tenant_id: str = os.getenv("ENTRA_ID_TENANT_ID")
    client_id: str = os.getenv("ENTRA_ID_CLIENT_ID")

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "Testing FastAPI with Entra ID",
            "message": "Testing FastAPI with Entra ID",
            "login_url": get_login_url(
                tenant_id=tenant_id,
                client_id=client_id,
                redirect_uri="http://localhost:8000",
            ),
            "logout_url": get_logout_url(
                tenant_id=tenant_id,
                client_id=client_id,
                redirect_uri="http://localhost:8000",
            ),
            "entra_id_tenant_id": tenant_id,
            "entra_id_client_id": client_id,
            "access_token": access_token,
            "id_token": id_token,
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
async def root(request: Request) -> JSONResponse:
    """A simple call with user authorization required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """

    if request.state.current_user is None:
        return get_stranger_message(request)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"Hello {request.state.current_user.name}"},
    )


@app.get(
    "/hello/admin",
    dependencies=[
        Depends(require_groups(["administrator"])),
    ],
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def root(request: Request) -> JSONResponse:
    """A simple call with admin authorization required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """

    if request.state.current_user is None:
        return get_stranger_message(request)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"Hello dear admin {request.state.current_user.name}"},
    )


@app.get(
    "/hello/customer",
    dependencies=[
        Depends(require_groups(["customer"])),
    ],
    response_class=JSONResponse,
    status_code=status.HTTP_200_OK,
)
async def root(request: Request) -> JSONResponse:
    """A simple call with customer authorization required

    Args:
        request (Request): FastAPI request object

    Returns:
        JSONResponse: a message
    """

    if request.state.current_user is None:
        return get_stranger_message(request)

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": f"Hello dear customer {request.state.current_user.name}"},
    )


if __name__ == "__main__":

    # Be careful!!! This call does not read the .env file
    run(app, host="0.0.0.0", port=8000)
