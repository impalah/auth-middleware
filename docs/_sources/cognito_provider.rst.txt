AWS Cognito Provider
===================

The AWS Cognito provider enables authentication and authorization using Amazon Cognito User Pools. This provider validates JWT tokens issued by Cognito and extracts user information and group memberships.

Overview
--------

AWS Cognito is a managed identity service that provides:

* **User Authentication**: Sign-up, sign-in, and user management
* **JWT Token Issuance**: Secure ID tokens for API access
* **Group Management**: Organize users into groups for authorization
* **Integration**: Seamless integration with AWS services

The Cognito provider in auth-middleware handles:

* JWT token validation and signature verification
* App client (``aud``/``client_id``) validation, when ``user_pool_client_id`` is configured
* User information extraction from tokens
* Group membership resolution
* Token expiration checking

Configuration
-------------

Basic Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.aws.cognito_provider import CognitoProvider
   from auth_middleware.providers.aws.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings,
   )
   from auth_middleware.providers.aws.cognito_groups_provider import (
       CognitoGroupsProvider,
   )

   # Configure Cognito settings
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_abcdef123",
       user_pool_region="us-east-1",
       user_pool_client_id="your-app-client-id",
       jwt_token_verification_disabled=False,
   )

   # Create Cognito provider
   cognito_provider = CognitoProvider(
       settings=auth_settings,
       groups_provider=CognitoGroupsProvider,
   )

   # Add to FastAPI application
   app.add_middleware(JwtAuthMiddleware, auth_provider=cognito_provider)

.. warning::

   ``user_pool_client_id`` is optional but strongly recommended. Cognito
   signs tokens for every app client in a user pool with the same JWKS, so
   signature verification alone accepts a valid token from *any* app
   client of that user pool. Setting ``user_pool_client_id`` makes
   ``CognitoProvider`` also check the token's ``aud`` claim (ID tokens) or
   ``client_id`` claim (access tokens) against it, and reject tokens
   issued for a different app client. Without it, this check is skipped
   for backward compatibility.

Environment Variables
~~~~~~~~~~~~~~~~~~~~

Set these environment variables for your application:

.. code-block:: bash

   # Required
   AWS_COGNITO_USER_POOL_ID=us-east-1_abcdef123
   AWS_COGNITO_USER_POOL_REGION=us-east-1
   
   # Optional
   TOKEN_VERIFICATION_DISABLED=false  # Set to true only for development

Example Application
------------------

Complete example with Cognito integration:

.. code-block:: python

   from fastapi import FastAPI, Depends
   from starlette.requests import Request
   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.guards import require_user, require_groups
   from auth_middleware.providers.aws.cognito_provider import CognitoProvider
   from auth_middleware.providers.aws.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings,
   )
   from auth_middleware.providers.aws.cognito_groups_provider import (
       CognitoGroupsProvider,
   )

   app = FastAPI(title="Cognito Example API")

   # Configuration
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_abcdef123",
       user_pool_region="us-east-1",
       jwt_token_verification_disabled=False,
   )

   # Setup middleware
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=CognitoProvider(
           settings=auth_settings,
           groups_provider=CognitoGroupsProvider,
       ),
   )

   # User endpoints
   @app.get("/profile", dependencies=[Depends(require_user())])
   async def get_profile(request: Request):
       user = request.state.current_user
       return {"user": user.name, "email": user.email, "groups": user.groups}

   # Admin endpoints
   @app.get("/admin", dependencies=[Depends(require_groups("admin"))])
   async def admin_only():
       return {"message": "Admin access granted"}

API Reference
-------------

.. automodule:: auth_middleware.providers.aws.cognito_provider
   :members:

.. automodule:: auth_middleware.providers.aws.cognito_authz_provider_settings
   :members:

.. automodule:: auth_middleware.providers.aws.cognito_groups_provider
   :members:
