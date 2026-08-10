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

   entra_id_provider
   oidc_provider

Services
--------

Additional services for cross-cutting concerns like M2M detection, rate limiting, audit logging, and metrics:

.. toctree::
   :maxdepth: 2

   services
   jwks-cache

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
   - :func:`auth_middleware.guards.functions.require_user` - Require authenticated user
   - :func:`auth_middleware.guards.functions.require_groups` - Require group membership
   - :func:`auth_middleware.guards.functions.require_permissions` - Require specific permissions
   - :func:`auth_middleware.guards.functions.get_current_user` - Get current user from request

**Providers**
   - :class:`auth_middleware.providers.oidc.oidc_provider.OidcProvider` - Generic OIDC (AWS Cognito, Authentik, Keycloak, Auth0, Okta, ...)
   - :class:`auth_middleware.providers.azure.entra_id_provider.EntraIdProvider` - Azure Entra ID
   - :class:`auth_middleware.contracts.jwt_provider.JWTProvider` - Base contract for building custom providers

**Exceptions**
   - :exc:`auth_middleware.exceptions.invalid_token_exception.InvalidTokenException` - Token validation failures

**Types**
   - :class:`auth_middleware.types.user.User` - User representation

Usage Patterns
---------------

Basic Setup
~~~~~~~~~~

.. code-block:: python

   from fastapi import FastAPI
   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.oidc.oidc_provider import OidcProvider
   from auth_middleware.providers.oidc.oidc_provider_settings import (
       OidcProviderSettings,
   )

   app = FastAPI()

   # Setup authentication. For AWS Cognito, issuer is
   # https://cognito-idp.{region}.amazonaws.com/{user_pool_id}
   auth_settings = OidcProviderSettings(
       issuer="https://your-issuer.example.com",
       audience="your-client-id",  # recommended: rejects tokens issued for other clients
   )
   auth_provider = OidcProvider(settings=auth_settings)

   app.add_middleware(JwtAuthMiddleware, auth_provider=auth_provider)

Endpoint Protection
~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from fastapi import Depends
   from auth_middleware.guards import require_user, require_groups

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
   from auth_middleware.exceptions.invalid_token_exception import InvalidTokenException

   @app.exception_handler(AuthenticationError)
   async def auth_error_handler(request, exc):
       return JSONResponse(
           status_code=401,
           content={"error": "Authentication failed"}
       )

