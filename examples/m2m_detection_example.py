"""
Example: Machine-to-Machine (M2M) Token Detection

This example demonstrates how to detect and handle M2M authentication
tokens versus regular user tokens.
"""

from fastapi import Depends, FastAPI, HTTPException, Request

from auth_middleware import JwtAuthMiddleware
from auth_middleware.functions import require_user
from auth_middleware.providers.authn.cognito_authz_provider_settings import (
    CognitoAuthzProviderSettings,
)
from auth_middleware.providers.authn.cognito_provider import CognitoProvider
from auth_middleware.services import M2MTokenDetector

# Initialize FastAPI
app = FastAPI(title="M2M Detection Example")

# Configure Cognito provider
settings = CognitoAuthzProviderSettings(
    user_pool_id="us-east-1_example",
    user_pool_region="us-east-1",
    user_pool_client_id="your-client-id",
)

auth_provider = CognitoProvider(settings=settings)

# Add authentication middleware
app.add_middleware(JwtAuthMiddleware, auth_provider=auth_provider)


@app.get("/user-only", dependencies=[Depends(require_user())])
async def user_only_endpoint(request: Request):
    """Endpoint that works for both users and M2M tokens."""
    user = request.state.current_user

    if user.is_m2m:
        return {
            "message": "Service account access",
            "client_id": user.client_id,
            "user_id": user.id,
        }
    else:
        return {
            "message": f"Welcome {user.email}",
            "user_id": user.id,
        }


@app.get("/humans-only", dependencies=[Depends(require_user())])
async def humans_only_endpoint(request: Request):
    """Endpoint that explicitly blocks M2M tokens."""
    user = request.state.current_user

    if user.is_m2m:
        raise HTTPException(
            status_code=403,
            detail="This endpoint requires human user authentication",
        )

    return {
        "message": f"Welcome human user {user.email}",
        "user_id": user.id,
    }


@app.get("/m2m-only", dependencies=[Depends(require_user())])
async def m2m_only_endpoint(request: Request):
    """Endpoint that only allows M2M tokens."""
    user = request.state.current_user

    if not user.is_m2m:
        raise HTTPException(
            status_code=403,
            detail="This endpoint is for service accounts only",
        )

    return {
        "message": "Service account authenticated",
        "client_id": user.client_id,
        "service_account_id": user.id,
    }


@app.get("/token-info", dependencies=[Depends(require_user())])
async def token_info(request: Request):
    """Show detailed information about the current token."""
    user = request.state.current_user

    # Detect M2M using utility (alternative approach)
    is_m2m = M2MTokenDetector.is_m2m_token(user.jwt_credentials.claims)
    client_id = M2MTokenDetector.get_client_id(user.jwt_credentials.claims)

    return {
        "token_type": "M2M" if is_m2m else "User",
        "user_id": user.id,
        "client_id": client_id,
        "email": user.email,
        "username": user.username,
        "is_m2m": user.is_m2m,
        "metadata": M2MTokenDetector.get_token_metadata(user.jwt_credentials.claims),
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
