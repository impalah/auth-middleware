Exception Handling
==================

This module defines the custom exceptions used throughout the auth-middleware library. These exceptions provide specific error handling for authentication and authorization scenarios.

Exception Hierarchy
-------------------

The auth-middleware library uses a hierarchical exception structure:

.. code-block:: text

   AuthMiddlewareException (base)
   ├── AuthenticationError
   ├── AuthorizationError
   └── ConfigurationError

Exception Types
--------------

AuthenticationError
~~~~~~~~~~~~~~~~~~

Raised when authentication fails, such as:

* Invalid or expired JWT tokens
* Missing authentication credentials
* Token validation failures
* Provider-specific authentication errors

.. code-block:: python

   from auth_middleware.exceptions import AuthenticationError
   
   try:
       user = await authenticate_user(token)
   except AuthenticationError as e:
       return JSONResponse(
           status_code=401,
           content={"error": "Authentication failed", "detail": str(e)}
       )

AuthorizationError
~~~~~~~~~~~~~~~~~

Raised when authorization checks fail, such as:

* Insufficient permissions
* Required group membership not met
* Access to protected resources denied

.. code-block:: python

   from auth_middleware.exceptions import AuthorizationError
   
   try:
       await check_user_permissions(user, required_permissions)
   except AuthorizationError as e:
       return JSONResponse(
           status_code=403,
           content={"error": "Access denied", "detail": str(e)}
       )

ConfigurationError
~~~~~~~~~~~~~~~~~

Raised when there are configuration issues, such as:

* Missing required environment variables
* Invalid provider settings
* Malformed configuration parameters

.. code-block:: python

   from auth_middleware.exceptions import ConfigurationError
   
   try:
       provider = create_auth_provider(settings)
   except ConfigurationError as e:
       logger.error(f"Configuration error: {e}")
       raise

Exception Handling Patterns
---------------------------

Middleware Error Handling
~~~~~~~~~~~~~~~~~~~~~~~~~

The middleware automatically handles exceptions and converts them to appropriate HTTP responses:

.. code-block:: python

   from fastapi import FastAPI, Request
   from fastapi.responses import JSONResponse
   from auth_middleware.exceptions import AuthenticationError, AuthorizationError

   app = FastAPI()

   @app.exception_handler(AuthenticationError)
   async def authentication_error_handler(request: Request, exc: AuthenticationError):
       return JSONResponse(
           status_code=401,
           content={
               "error": "authentication_failed",
               "message": str(exc),
               "type": "AuthenticationError"
           }
       )

   @app.exception_handler(AuthorizationError)
   async def authorization_error_handler(request: Request, exc: AuthorizationError):
       return JSONResponse(
           status_code=403,
           content={
               "error": "access_denied",
               "message": str(exc),
               "type": "AuthorizationError"
           }
       )

Custom Error Responses
~~~~~~~~~~~~~~~~~~~~~

You can customize error responses based on the authentication provider:

.. code-block:: python

   @app.exception_handler(AuthenticationError)
   async def custom_auth_error_handler(request: Request, exc: AuthenticationError):
       # Customize response based on provider type
       provider_type = getattr(request.state, 'auth_provider_type', 'unknown')
       
       if provider_type == 'cognito':
           return JSONResponse(
               status_code=401,
               content={
                   "error": "invalid_token",
                   "error_description": "AWS Cognito authentication failed",
                   "error_uri": "https://docs.aws.amazon.com/cognito/"
               }
           )
       elif provider_type == 'entra_id':
           return JSONResponse(
               status_code=401,
               content={
                   "error": "invalid_token",
                   "error_description": "Azure AD authentication failed",
                   "error_uri": "https://docs.microsoft.com/azure/active-directory/"
               }
           )
       
       return JSONResponse(
           status_code=401,
           content={"error": "authentication_failed", "message": str(exc)}
       )

Logging Exceptions
~~~~~~~~~~~~~~~~~

It's recommended to log exceptions for debugging and monitoring:

.. code-block:: python

   import logging
   from auth_middleware.exceptions import AuthMiddlewareException

   logger = logging.getLogger(__name__)

   @app.exception_handler(AuthMiddlewareException)
   async def log_auth_errors(request: Request, exc: AuthMiddlewareException):
       logger.warning(
           f"Auth error: {exc.__class__.__name__}: {exc}",
           extra={
               "path": request.url.path,
               "method": request.method,
               "client": request.client.host if request.client else None,
               "user_agent": request.headers.get("user-agent"),
           }
       )
       
       # Re-raise to let other handlers process it
       raise exc

API Reference
-------------

.. automodule:: auth_middleware.exceptions
   :members:
