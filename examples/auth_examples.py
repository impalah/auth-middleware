#!/usr/bin/env python3
"""
Example of how to configure different cache backends with dependency injection
"""


from fastapi import Depends, FastAPI
from fastapi.openapi.utils import get_openapi

from auth_middleware.functions import require_groups, require_user
from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.cognito_provider import CognitoProvider
from auth_middleware.providers.authz.cognito_groups_provider import (
    CognitoGroupsProvider,
)

# Configuration for Cognito provider
# TODO: Set your own parameters
configuration: dict[str, str] = {
    "USER_POOL_ID": "your_user_pool_id",
    "AWS_REGION": "your_aws_region",
    "TOKEN_VERIFICATION_DISABLED": False,  # or "True" based on your needs
}


def custom_openapi(app: FastAPI):
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
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


def create_app_with_cognito():
    """Application with Cognito backend"""

    app = FastAPI(title="App - Cognito")

    auth_provider_settings: CognitoAuthzProviderSettings = CognitoAuthzProviderSettings(
        user_pool_id=configuration["USER_POOL_ID"],
        user_pool_region=configuration["AWS_REGION"],
        jwt_token_verification_disabled=configuration["TOKEN_VERIFICATION_DISABLED"],
    )

    app.add_middleware(
        JwtAuthMiddleware,
        auth_provider=CognitoProvider(
            settings=auth_provider_settings,
            groups_provider=CognitoGroupsProvider,
            # permissions_provider=SqlPermissionsProvider,
        ),
    )

    return app


# Example endpoints for any app
async def get_items(q: str = None, page: int = 1):
    return {"query": q, "page": page, "result": [f"item-{i}" for i in range(1, 6)]}


async def get_user(user_id: int):
    return {
        "id": user_id,
        "name": f"User {user_id}",
        "email": f"user{user_id}@example.com",
    }


async def calculate(data: dict):
    """
    Calculate the sum of numbers with caching.

    This endpoint demonstrates caching for POST requests with body content.
    The cache key includes the request body to ensure different inputs
    are cached separately.

    Parameters
    ----------
    data : dict
        Dictionary containing a 'numbers' key with a list of numbers

    Returns
    -------
    dict
        Dictionary with the original input and the calculated sum
    """
    if data is None:
        data = {}
    # Simulate expensive operation
    result = sum(data.get("numbers", []))
    return {"input": data, "sum": result}


def setup_app_routes(app: FastAPI):
    """Add example routes to any app"""
    app.add_api_route(
        "/items", get_items, methods=["GET"], dependencies=[Depends(require_user())]
    )
    app.add_api_route(
        "/users/{user_id}",
        get_user,
        methods=["GET"],
        dependencies=[Depends(require_groups("admin"))],
    )
    app.add_api_route("/calculate", calculate, methods=["POST"])


if __name__ == "__main__":
    import uvicorn

    # Build available apps based on installed dependencies
    apps = {
        "cognito": create_app_with_cognito,
    }

    # Change to the backend type you want to test
    app_type = "cognito"

    if app_type not in apps:
        available_types = list(apps.keys())
        raise ValueError(
            f"Backend '{app_type}' not available. Available: {available_types}"
        )

    # Create the selected app
    app = apps[app_type]()

    # Add Openapi custom config
    app.openapi = lambda: custom_openapi(app)

    # Add endpoints
    setup_app_routes(app)

    print(f"Available backends: {list(apps.keys())}")
    print(f"Using backend: {app_type}")
    print("Starting server at http://localhost:8000")
    print("Test: http://localhost:8000/items?q=test&page=1")

    uvicorn.run(app, host="0.0.0.0", port=8000)
