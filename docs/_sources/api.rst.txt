API Reference
=============

This section provides comprehensive API documentation for all components of the auth-middleware library.

Core Components
---------------

.. toctree::
   :maxdepth: 2

   jwt_auth_middleware
   functions
   types
   exceptions

Authentication Providers
------------------------

The library supports multiple authentication providers for different identity systems:

.. toctree::
   :maxdepth: 2

   cognito_provider
   entra_id_provider
   jwt_auth_provider

Utilities
---------

Additional utilities and helper components:

.. toctree::
   :maxdepth: 2

   jwt_bearer_manager
   user-property

Quick Reference
---------------

Common Classes and Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Middleware**
   - :class:`auth_middleware.JwtAuthMiddleware` - Main authentication middleware

**Authentication Functions**
   - :func:`auth_middleware.require_user` - Require authenticated user
   - :func:`auth_middleware.require_groups` - Require group membership
   - :func:`auth_middleware.require_permissions` - Require specific permissions
   - :func:`auth_middleware.get_current_user` - Get current user from request

**Providers**
   - :class:`auth_middleware.providers.authn.cognito_provider.CognitoProvider` - AWS Cognito
   - :class:`auth_middleware.providers.authn.entra_id_provider.EntraIdProvider` - Azure Entra ID
   - :class:`auth_middleware.providers.authn.jwt_provider.JWTProvider` - Generic JWT

**Exceptions**
   - :exc:`auth_middleware.exceptions.AuthenticationError` - Authentication failures
   - :exc:`auth_middleware.exceptions.AuthorizationError` - Authorization failures
   - :exc:`auth_middleware.exceptions.ConfigurationError` - Configuration issues

**Types**
   - :class:`auth_middleware.types.User` - User representation
   - :class:`auth_middleware.types.AuthenticatedRequest` - Extended request with auth context

Usage Patterns
---------------

Basic Setup
~~~~~~~~~~

.. code-block:: python

   from fastapi import FastAPI
   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider

   app = FastAPI()
   
   # Setup authentication
   auth_provider = CognitoProvider(
       user_pool_id="your-user-pool-id",
       client_id="your-client-id",
       region="us-east-1"
   )
   
   app.add_middleware(JwtAuthMiddleware, auth_provider=auth_provider)

Endpoint Protection
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from fastapi import Depends
   from auth_middleware import require_user, require_groups

   @app.get("/protected", dependencies=[Depends(require_user())])
   async def protected_endpoint(request):
       user = request.state.current_user
       return {"message": f"Hello {user.name}"}

   @app.get("/admin", dependencies=[Depends(require_groups(["administrators"]))])
   async def admin_endpoint(request):
       return {"message": "Admin access granted"}

Error Handling
~~~~~~~~~~~~~

.. code-block:: python

   from fastapi.responses import JSONResponse
   from auth_middleware.exceptions import AuthenticationError, AuthorizationError

   @app.exception_handler(AuthenticationError)
   async def auth_error_handler(request, exc):
       return JSONResponse(
           status_code=401,
           content={"error": "Authentication failed"}
       )

   @app.exception_handler(AuthorizationError)
   async def authz_error_handler(request, exc):
       return JSONResponse(
           status_code=403,
           content={"error": "Access denied"}
       )

