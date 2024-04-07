import os
from typing import Optional
from fastapi import FastAPI, Depends, status
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from uvicorn import run

from starlette.requests import Request
from starlette.responses import Response

from auth_middleware.functions import require_groups, require_user
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
from auth_middleware.providers.cognito import CognitoProvider

templates = Jinja2Templates(directory="templates")

app: FastAPI = FastAPI()
app.add_middleware(JwtAuthMiddleware, auth_provider=CognitoProvider())

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



@app.get(
    "/",
    response_class=HTMLResponse
)
async def index(
    request: Request,
    access_token: Optional[str] = None,
    id_token: Optional[str] = None
) -> HTMLResponse:
    
    # Get variables from environment
    cognito_domain: str = os.getenv("COGNITO_DOMAIN")
    cognito_client_id: str = os.getenv("COGNITO_CLIENT_ID")
    region: str = os.getenv("AWS_REGION")
    
    
    login_url: str = f"https://{cognito_domain}.auth.{region}.amazoncognito.com/login?client_id={cognito_client_id}&response_type=token&scope=email+openid+phone+profile&redirect_uri=http%3A%2F%2Flocalhost%3A8000"
    logout_url : str = f"https://{cognito_domain}.auth.{region}.amazoncognito.com/logout?client_id={cognito_client_id}&response_type=token&redirect_uri=http%3A%2F%2Flocalhost%3A8000"    
    print (logout_url)
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "title": "Testing FastAPI with Cognito",
            "message": "Testing FastAPI with Cognito",
            "login_url": login_url,
            "logout_url": logout_url,
            "cognito_domain": cognito_domain,
            "region": region,
            "cognito_client_id": cognito_client_id,
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


@app.get("/hello/admin",
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


@app.get("/hello/customer",
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
