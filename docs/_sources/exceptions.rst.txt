Exception Handling
==================

This module defines the custom exceptions used throughout the auth-middleware library. These exceptions provide specific error handling for authentication and authorization scenarios.

Exception Types
--------------

InvalidTokenException
~~~~~~~~~~~~~~~~~~~~~

The primary exception raised during token validation failures. Carries an HTTP status code and detail message.

Common causes:

* Invalid or expired JWT tokens
* Missing or malformed Authorization header
* No public key found for the token
* Token signature verification failure

.. code-block:: python

   from auth_middleware.exceptions import InvalidTokenException

   try:
       user = await authenticate_user(token)
   except InvalidTokenException as e:
       return JSONResponse(
           status_code=e.status_code,
           content={"error": "Token error", "detail": e.detail}
       )

AuthenticationError
~~~~~~~~~~~~~~~~~~~

Raised when low-level authentication fails (e.g., HMAC computation, credential decoding).

.. code-block:: python

   from auth_middleware.exceptions import AuthenticationError

   try:
       result = await provider.verify_token(credentials)
   except AuthenticationError as e:
       logger.warning(f"Authentication error: {e}")

InvalidAuthorizationException
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Raised when the Authorization header is present but malformed (wrong scheme, missing parts).

.. code-block:: python

   from auth_middleware.exceptions import InvalidAuthorizationException

InvalidCredentialsException
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Raised when Basic Auth credentials are invalid (wrong username or password).

.. code-block:: python

   from auth_middleware.exceptions import InvalidCredentialsException

UserNotFoundError
~~~~~~~~~~~~~~~~~

Raised when a user cannot be found in the identity provider.

.. code-block:: python

   from auth_middleware.exceptions import UserNotFoundError

PasswordPolicyError
~~~~~~~~~~~~~~~~~~~

Raised when a password change fails due to policy requirements.

.. code-block:: python

   from auth_middleware.exceptions import PasswordPolicyError

Exception Handling Patterns
---------------------------

Global Exception Handler
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from fastapi import FastAPI, Request
   from fastapi.responses import JSONResponse
   from auth_middleware.exceptions import InvalidTokenException, AuthenticationError

   app = FastAPI()

   @app.exception_handler(InvalidTokenException)
   async def invalid_token_handler(request: Request, exc: InvalidTokenException):
       return JSONResponse(
           status_code=exc.status_code,
           content={
               "error": "token_error",
               "message": exc.detail,
           }
       )

   @app.exception_handler(AuthenticationError)
   async def authentication_error_handler(request: Request, exc: AuthenticationError):
       return JSONResponse(
           status_code=401,
           content={
               "error": "authentication_failed",
               "message": str(exc),
           }
       )

API Reference
-------------

.. automodule:: auth_middleware.exceptions
   :members:
