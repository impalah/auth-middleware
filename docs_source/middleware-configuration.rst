Middleware Configuration
========================

This section covers advanced configuration options for Auth Middleware, including environment variables, custom providers, and performance tuning.

Basic Middleware Setup
---------------------

The Auth Middleware is added to your FastAPI or Starlette application using the standard middleware protocol:

.. code-block:: python

   from fastapi import FastAPI
   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider

   app = FastAPI()

   # Add authentication middleware
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=your_auth_provider,
       # Additional configuration options...
   )

Middleware Parameters
--------------------

The ``JwtAuthMiddleware`` accepts the following parameters:

.. list-table::
   :header-rows: 1
   :widths: 20 30 20 30

   * - Parameter
     - Description
     - Type
     - Default
   * - ``auth_provider``
     - The authentication provider instance
     - ``AuthProvider``
     - Required
   * - ``exclude_paths``
     - Paths to exclude from authentication
     - ``List[str]``
     - ``[]``
   * - ``include_paths``
     - Paths to include in authentication
     - ``List[str]``
     - ``["/*"]``
   * - ``auth_header_name``
     - HTTP header for authentication token
     - ``str``
     - ``"Authorization"``
   * - ``auth_scheme``
     - Authentication scheme
     - ``str``
     - ``"Bearer"``

Path Configuration
-----------------

Excluding Paths from Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can exclude specific paths from authentication requirements:

.. code-block:: python

   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=cognito_provider,
       exclude_paths=[
           "/",                    # Public homepage
           "/health",              # Health check endpoint
           "/docs",                # OpenAPI documentation
           "/openapi.json",        # OpenAPI schema
           "/metrics",             # Prometheus metrics
           "/static/*",            # Static files
           "/public/*",            # Public assets
       ]
   )

Including Specific Paths Only
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Alternatively, you can specify only the paths that require authentication:

.. code-block:: python

   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=cognito_provider,
       include_paths=[
           "/api/*",               # All API endpoints
           "/admin/*",             # Admin interface
           "/user/*",              # User-specific endpoints
       ]
   )

Pattern Matching
~~~~~~~~~~~~~~~

The middleware supports glob-style pattern matching:

* ``*`` matches any characters within a single path segment
* ``**`` matches any characters across multiple path segments
* ``?`` matches any single character

.. code-block:: python

   exclude_paths = [
       "/api/v*/public/*",     # Version-specific public endpoints
       "/health*",             # All health-related endpoints
       "/static/**",           # All static files recursively
   ]

Environment Variables
--------------------

Core Configuration
~~~~~~~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 30 40 30

   * - Environment Variable
     - Description
     - Default
   * - ``AUTH_MIDDLEWARE_DISABLED``
     - Disable all authentication
     - ``false``
   * - ``AUTH_MIDDLEWARE_LOG_LEVEL``
     - Logging level
     - ``INFO``
   * - ``AUTH_MIDDLEWARE_LOGGER_NAME``
     - Logger name
     - ``auth_middleware``

Provider-Specific Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~

**AWS Cognito**:

.. code-block:: bash

   AWS_COGNITO_USER_POOL_ID=us-east-1_abcdef123
   AWS_COGNITO_USER_POOL_REGION=us-east-1
   TOKEN_VERIFICATION_DISABLED=false

**Azure Entra ID**:

.. code-block:: bash

   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-client-id
   AZURE_CLIENT_SECRET=your-client-secret

**JWT Provider**:

.. code-block:: bash

   JWT_SECRET_KEY=your-secret-key
   JWT_ALGORITHM=HS256
   JWT_ISSUER=your-issuer

Custom Authentication Providers
------------------------------

Creating a Custom Provider
~~~~~~~~~~~~~~~~~~~~~~~~~

You can create custom authentication providers by implementing the ``AuthProvider`` interface:

.. code-block:: python

   from abc import ABC, abstractmethod
   from typing import Optional
   from auth_middleware.types import User

   class CustomAuthProvider(ABC):
       @abstractmethod
       async def authenticate(self, token: str) -> Optional[User]:
           """Validate token and return user information."""
           pass

       @abstractmethod
       async def get_user_groups(self, user: User) -> List[str]:
           """Get user group memberships."""
           pass

Example Custom Provider
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import jwt
   from auth_middleware.types import User
   from auth_middleware.exceptions import AuthenticationError

   class ApiKeyProvider:
       def __init__(self, valid_api_keys: dict):
           self.valid_api_keys = valid_api_keys

       async def authenticate(self, token: str) -> Optional[User]:
           # Remove 'Bearer ' prefix if present
           if token.startswith('Bearer '):
               token = token[7:]

           # Look up API key
           user_info = self.valid_api_keys.get(token)
           if not user_info:
               raise AuthenticationError("Invalid API key")

           return User(
               id=user_info["id"],
               name=user_info["name"],
               email=user_info["email"],
               groups=user_info.get("groups", []),
               raw_token=token,
           )

       async def get_user_groups(self, user: User) -> List[str]:
           return user.groups

   # Usage
   api_keys = {
       "api_key_123": {
           "id": "user1",
           "name": "John Doe",
           "email": "john@example.com",
           "groups": ["user", "admin"]
       }
   }

   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=ApiKeyProvider(api_keys)
   )

Performance Configuration
------------------------

Connection Pooling
~~~~~~~~~~~~~~~~~

For providers that make HTTP requests (like Cognito), configure connection pooling:

.. code-block:: python

   import httpx
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider

   # Custom HTTP client with connection pooling
   http_client = httpx.AsyncClient(
       timeout=30.0,
       limits=httpx.Limits(
           max_keepalive_connections=10,
           max_connections=100,
       )
   )

   # Note: This is conceptual - actual implementation may vary
   cognito_provider = CognitoProvider(
       settings=auth_settings,
       http_client=http_client,
   )

Caching Configuration
~~~~~~~~~~~~~~~~~~~

Token validation results can be cached to improve performance:

.. code-block:: python

   # This is conceptual - check actual provider documentation
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_abcdef123",
       user_pool_region="us-east-1",
       cache_jwks=True,              # Cache JSON Web Key Sets
       cache_ttl=3600,               # Cache TTL in seconds
   )

Logging Configuration
--------------------

Detailed Logging
~~~~~~~~~~~~~~~

Enable detailed logging for debugging:

.. code-block:: python

   import logging

   # Configure auth middleware logging
   auth_logger = logging.getLogger("auth_middleware")
   auth_logger.setLevel(logging.DEBUG)

   # Add handler
   handler = logging.StreamHandler()
   formatter = logging.Formatter(
       '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
   )
   handler.setFormatter(formatter)
   auth_logger.addHandler(handler)

Environment-based Logging
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Set log level via environment
   AUTH_MIDDLEWARE_LOG_LEVEL=DEBUG
   AUTH_MIDDLEWARE_LOG_FORMAT="%(asctime)s %(name)s %(levelname)s %(message)s"
   AUTH_MIDDLEWARE_LOGGER_NAME="my_auth"

Security Best Practices
-----------------------

Token Security
~~~~~~~~~~~~~

1. **Use HTTPS**: Always use HTTPS in production to protect tokens in transit
2. **Token Expiration**: Ensure tokens have reasonable expiration times
3. **Secure Storage**: Never log or store JWT tokens in plain text
4. **Rotation**: Implement token rotation strategies

Configuration Security
~~~~~~~~~~~~~~~~~~~~~

1. **Environment Variables**: Store sensitive configuration in environment variables
2. **Secrets Management**: Use proper secrets management systems in production
3. **Least Privilege**: Configure minimal required permissions
4. **Monitoring**: Monitor authentication failures and suspicious activity

Error Handling Configuration
---------------------------

Custom Error Handlers
~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from fastapi import FastAPI, HTTPException
   from fastapi.responses import JSONResponse
   from auth_middleware.exceptions import (
       AuthenticationError,
       AuthorizationError,
       TokenExpiredError,
   )

   app = FastAPI()

   @app.exception_handler(AuthenticationError)
   async def authentication_error_handler(request, exc):
       return JSONResponse(
           status_code=401,
           content={
               "error": "Authentication Failed",
               "message": "Please provide a valid authentication token",
               "type": "authentication_error"
           }
       )

   @app.exception_handler(AuthorizationError)
   async def authorization_error_handler(request, exc):
       return JSONResponse(
           status_code=403,
           content={
               "error": "Access Denied",
               "message": "You don't have permission to access this resource",
               "type": "authorization_error"
           }
       )

   @app.exception_handler(TokenExpiredError)
   async def token_expired_handler(request, exc):
       return JSONResponse(
           status_code=401,
           content={
               "error": "Token Expired",
               "message": "Your authentication token has expired. Please login again",
               "type": "token_expired"
           }
       )

Development Configuration
------------------------

Development Mode
~~~~~~~~~~~~~~

For development and testing environments:

.. code-block:: python

   import os

   # Development-friendly configuration
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id=os.getenv("AWS_COGNITO_USER_POOL_ID"),
       user_pool_region=os.getenv("AWS_COGNITO_USER_POOL_REGION"),
       jwt_token_verification_disabled=os.getenv("ENVIRONMENT") == "development",
   )

Hot Reloading
~~~~~~~~~~~

Auth Middleware works with FastAPI's hot reloading in development:

.. code-block:: bash

   # Development server with hot reloading
   uvicorn main:app --reload --host 0.0.0.0 --port 8000

Testing Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import pytest
   from fastapi.testclient import TestClient

   @pytest.fixture
   def test_app():
       app = FastAPI()
       
       # Use mock auth provider for testing
       app.add_middleware(
           JwtAuthMiddleware,
           auth_provider=MockAuthProvider(),
       )
       
       return app

   def test_protected_endpoint(test_app):
       client = TestClient(test_app)
       
       response = client.get(
           "/protected",
           headers={"Authorization": "Bearer test_token"}
       )
       
       assert response.status_code == 200

For more specific provider configurations, see the individual provider documentation:

* :doc:`cognito_provider`
* :doc:`entra_id_provider`
* :doc:`jwt_auth_provider`
   * - AUTH_MIDDLEWARE_JWKS_CACHE_INTERVAL_MINUTES
     - JWKS keys file refreshing interval
     - An integer value
     - 20
   * - AUTH_MIDDLEWARE_JWKS_CACHE_USAGES
     - JWKS keys refreshing interval (counter)
     - An integer value
     - 1000