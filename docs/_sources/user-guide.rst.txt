User Guide
==========

This guide will walk you through setting up and using Auth Middleware in your FastAPI or Starlette application. Auth Middleware provides authentication and authorization capabilities with support for multiple identity providers.

Overview
--------

Auth Middleware follows the ASGI middleware protocol and integrates seamlessly with FastAPI and Starlette applications. It supports:

* **JWT Authentication**: Validate and process JWT tokens
* **Multiple Providers**: AWS Cognito, Azure Entra ID, Google, and custom providers
* **Authorization**: Group-based and permission-based access control
* **Type Safety**: Full type hints for better development experience

Basic Setup
-----------

The basic setup involves three steps:

1. **Configure the authentication provider**
2. **Add the middleware to your application**
3. **Protect endpoints with dependency injection**

AWS Cognito Example
-------------------

Here's a complete example using AWS Cognito as the authentication provider:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from starlette.requests import Request
   from auth_middleware import JwtAuthMiddleware, require_user, require_groups
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider
   from auth_middleware.providers.authn.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings,
   )
   from auth_middleware.providers.authz.cognito_groups_provider import (
       CognitoGroupsProvider,
   )

   # Create FastAPI application
   app = FastAPI(title="My Secure API", version="1.0.0")

   # Configure Cognito authentication settings
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id="your_user_pool_id",
       user_pool_region="your_aws_region",
       jwt_token_verification_disabled=False,  # Set to True for development only
   )

   # Add authentication middleware
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=CognitoProvider(
           settings=auth_settings,
           groups_provider=CognitoGroupsProvider,
       ),
   )

   # Public endpoint (no authentication required)
   @app.get("/")
   async def public_endpoint():
       return {"message": "This is a public endpoint"}

   # Protected endpoint (requires valid JWT token)
   @app.get("/protected", dependencies=[Depends(require_user())])
   async def protected_endpoint(request: Request):
       user = request.state.current_user
       return {
           "message": f"Hello {user.name}",
           "user_id": user.id,
           "groups": user.groups,
       }

   # Admin-only endpoint (requires 'admin' group membership)
   @app.get("/admin", dependencies=[Depends(require_groups("admin"))])
   async def admin_endpoint(request: Request):
       return {"message": "Admin access granted"}

   # Multiple groups allowed
   @app.get("/managers", dependencies=[Depends(require_groups(["admin", "manager"]))])
   async def managers_endpoint():
       return {"message": "Manager or admin access granted"}

Environment Configuration
-------------------------

Set the required environment variables for your authentication provider:

**AWS Cognito** (alternative to hardcoded settings):

.. code-block:: bash

   # .env file or environment variables
   AWS_COGNITO_USER_POOL_ID=your_user_pool_id
   AWS_COGNITO_USER_POOL_REGION=your_aws_region
   TOKEN_VERIFICATION_DISABLED=false

**Environment-based configuration**:

.. code-block:: python

   import os
   from auth_middleware.providers.authn.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings,
   )

   # Load from environment variables
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id=os.getenv("AWS_COGNITO_USER_POOL_ID"),
       user_pool_region=os.getenv("AWS_COGNITO_USER_POOL_REGION"),
       jwt_token_verification_disabled=os.getenv("TOKEN_VERIFICATION_DISABLED", "false").lower() == "true",
   )

OpenAPI Integration
------------------

Auth Middleware integrates with FastAPI's OpenAPI documentation to provide proper security schemas:

.. code-block:: python

   from fastapi.openapi.utils import get_openapi

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
               if isinstance(method, dict):
                   method["security"] = [{"bearerAuth": []}]

       app.openapi_schema = openapi_schema
       return app.openapi_schema

   # Apply custom OpenAPI
   app.openapi = lambda: custom_openapi(app)

Making Requests
---------------

Once your application is protected, clients need to include JWT tokens in their requests:

**cURL example**:

.. code-block:: bash

   # Get a JWT token from your identity provider first
   export JWT_TOKEN="your_jwt_token_here"

   # Make authenticated requests
   curl -X GET http://localhost:8000/protected \
        -H "Authorization: Bearer $JWT_TOKEN"

**Python requests example**:

.. code-block:: python

   import requests

   headers = {
       "Authorization": "Bearer your_jwt_token_here",
       "Content-Type": "application/json"
   }

   response = requests.get("http://localhost:8000/protected", headers=headers)
   print(response.json())

Accessing User Information
-------------------------

Within protected endpoints, you can access the current user information:

.. code-block:: python

   from starlette.requests import Request
   from auth_middleware import get_current_user

   @app.get("/user-info", dependencies=[Depends(require_user())])
   async def get_user_info(request: Request):
       user = request.state.current_user
       
       return {
           "id": user.id,
           "name": user.name,
           "email": user.email,
           "groups": user.groups,
           "permissions": user.permissions,
           "raw_token": user.raw_token,  # Original JWT token
       }

   # Alternative using dependency injection
   @app.get("/user-profile")
   async def get_user_profile(current_user=Depends(get_current_user())):
       return {
           "profile": {
               "name": current_user.name,
               "email": current_user.email,
           }
       }

Error Handling
--------------

Auth Middleware provides specific exceptions for different authentication and authorization scenarios:

.. code-block:: python

   from fastapi import HTTPException
   from auth_middleware.exceptions import (
       AuthenticationError,
       AuthorizationError,
       InvalidTokenError,
   )

   @app.exception_handler(AuthenticationError)
   async def authentication_exception_handler(request, exc):
       return JSONResponse(
           status_code=401,
           content={"error": "Authentication failed", "detail": str(exc)}
       )

   @app.exception_handler(AuthorizationError)
   async def authorization_exception_handler(request, exc):
       return JSONResponse(
           status_code=403,
           content={"error": "Access denied", "detail": str(exc)}
       )

Development Tips
---------------

**Disable Token Verification for Development**:

.. code-block:: python

   # Only for development/testing
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id="your_user_pool_id",
       user_pool_region="your_aws_region",
       jwt_token_verification_disabled=True,  # Skip signature verification
   )

**Logging Configuration**:

.. code-block:: python

   import logging
   
   # Enable debug logging for auth middleware
   logging.getLogger("auth_middleware").setLevel(logging.DEBUG)

**Testing Protected Endpoints**:

.. code-block:: python

   from fastapi.testclient import TestClient
   
   client = TestClient(app)
   
   # Test with valid token
   headers = {"Authorization": "Bearer valid_jwt_token"}
   response = client.get("/protected", headers=headers)
   assert response.status_code == 200
   
   # Test without token
   response = client.get("/protected")
   assert response.status_code == 401

Next Steps
----------

* Learn about :doc:`middleware-configuration` for advanced settings
* Explore other :doc:`cognito_provider` for different identity providers
* Check the :doc:`api` reference for detailed API documentation