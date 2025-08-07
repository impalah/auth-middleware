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
* User information extraction from tokens
* Group membership resolution
* Token expiration checking

Configuration
-------------

Basic Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider
   from auth_middleware.providers.authn.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings,
   )
   from auth_middleware.providers.authz.cognito_groups_provider import (
       CognitoGroupsProvider,
   )

   # Configure Cognito settings
   auth_settings = CognitoAuthzProviderSettings(
       user_pool_id="us-east-1_abcdef123",
       user_pool_region="us-east-1",
       jwt_token_verification_disabled=False,
   )

   # Create Cognito provider
   cognito_provider = CognitoProvider(
       settings=auth_settings,
       groups_provider=CognitoGroupsProvider,
   )

   # Add to FastAPI application
   app.add_middleware(JwtAuthMiddleware, auth_provider=cognito_provider)

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
   from auth_middleware import JwtAuthMiddleware, require_user, require_groups
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider
   from auth_middleware.providers.authn.cognito_authz_provider_settings import (
       CognitoAuthzProviderSettings,
   )
   from auth_middleware.providers.authz.cognito_groups_provider import (
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

.. automodule:: auth_middleware.providers.authn.cognito_provider
   :members:

.. automodule:: auth_middleware.providers.authn.cognito_authz_provider_settings
   :members:

.. automodule:: auth_middleware.providers.authz.cognito_groups_provider
   :members:
