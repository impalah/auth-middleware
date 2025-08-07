Azure Entra ID Authentication Provider
======================================

The Azure Entra ID (formerly Azure Active Directory) Authentication Provider enables JWT token validation against Microsoft's identity platform. This provider automatically handles token validation using Azure's public keys and supports both single-tenant and multi-tenant applications.

Overview
--------

The Entra ID provider supports:

* **Automatic Key Rotation**: Fetches public keys from Microsoft's JWKS endpoint
* **Multi-tenant Support**: Validates tokens from any Azure AD tenant
* **Claims Mapping**: Maps Azure AD claims to user information
* **Group Integration**: Supports Azure AD security groups and roles
* **Token Validation**: Full JWT validation including signature, expiration, and issuer

Configuration
-------------

Basic Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.authn.entra_id_provider import EntraIdProvider
   from auth_middleware.providers.authn.entra_id_provider_settings import EntraIdProviderSettings

   # Configure Entra ID settings
   entra_settings = EntraIdProviderSettings(
       tenant_id="your-tenant-id",
       client_id="your-application-id",
       issuer="https://sts.windows.net/your-tenant-id/",
   )

   # Create Entra ID provider
   entra_provider = EntraIdProvider(settings=entra_settings)

   # Add to FastAPI application
   app.add_middleware(JwtAuthMiddleware, auth_provider=entra_provider)

Multi-tenant Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

For applications that need to accept users from any Azure AD tenant:

.. code-block:: python

   entra_settings = EntraIdProviderSettings(
       tenant_id="common",  # Accept from any tenant
       client_id="your-application-id",
       issuer="https://sts.windows.net/",  # Generic issuer for multi-tenant
       validate_tenant=False,  # Skip tenant validation
   )

Environment Variables
--------------------

Required Environment Variables
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Required
   ENTRA_TENANT_ID=your-tenant-id-or-common
   ENTRA_CLIENT_ID=your-application-client-id
   
   # Optional
   ENTRA_ISSUER=https://sts.windows.net/your-tenant-id/
   ENTRA_AUDIENCE=your-application-id-uri
   ENTRA_VALIDATE_TENANT=true

Environment-based Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   import os
   from auth_middleware.providers.authn.entra_id_provider_settings import EntraIdProviderSettings

   def create_entra_settings():
       return EntraIdProviderSettings(
           tenant_id=os.getenv("ENTRA_TENANT_ID"),
           client_id=os.getenv("ENTRA_CLIENT_ID"),
           issuer=os.getenv("ENTRA_ISSUER"),
           audience=os.getenv("ENTRA_AUDIENCE"),
           validate_tenant=os.getenv("ENTRA_VALIDATE_TENANT", "true").lower() == "true",
       )

Token Structure
--------------

Expected Entra ID Claims
~~~~~~~~~~~~~~~~~~~~~~~~

Azure Entra ID tokens contain the following claims:

.. code-block:: json

   {
     "aud": "your-application-id",
     "iss": "https://sts.windows.net/tenant-id/",
     "iat": 1640908800,
     "exp": 1640995200,
     "sub": "AAAAAAAAAAAAAAAAAAAAAMLkj3QiQZ-KiFQjQ",
     "name": "John Doe",
     "preferred_username": "john@company.com",
     "email": "john@company.com",
     "tid": "tenant-id",
     "oid": "object-id",
     "groups": ["group-id-1", "group-id-2"],
     "roles": ["Role.Admin", "Role.User"],
     "scp": "User.Read Profile.Read"
   }

User Information Mapping
~~~~~~~~~~~~~~~~~~~~~~~

The provider maps Entra ID claims to user information:

.. code-block:: python

   class EntraIdUser:
       id: str              # From 'oid' claim
       name: str            # From 'name' claim
       email: str           # From 'email' or 'preferred_username'
       tenant_id: str       # From 'tid' claim
       groups: List[str]    # From 'groups' claim
       roles: List[str]     # From 'roles' claim
       scopes: List[str]    # From 'scp' claim (space-separated)

Azure AD App Registration
------------------------

Application Setup
~~~~~~~~~~~~~~~~

1. **Register Application**: Go to Azure Portal > App registrations > New registration
2. **Configure Authentication**: Set redirect URIs and supported account types
3. **API Permissions**: Add required Microsoft Graph permissions
4. **Expose API**: Configure application ID URI and scopes

App Registration Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: json

   {
     "displayName": "Your API Application",
     "signInAudience": "AzureADMyOrg",  // Single tenant
     "identifierUris": [
       "api://your-application-id"
     ],
     "requiredResourceAccess": [
       {
         "resourceAppId": "00000003-0000-0000-c000-000000000000",  // Microsoft Graph
         "resourceAccess": [
           {
             "id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  // User.Read
             "type": "Scope"
           }
         ]
       }
     ]
   }

Integration Examples
-------------------

Single-tenant Application
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from fastapi import FastAPI, Depends
   from auth_middleware import JwtAuthMiddleware, require_user, require_groups
   from auth_middleware.providers.authn.entra_id_provider import EntraIdProvider
   from auth_middleware.providers.authn.entra_id_provider_settings import EntraIdProviderSettings

   app = FastAPI(title="Enterprise API")

   # Single-tenant configuration
   entra_settings = EntraIdProviderSettings(
       tenant_id="12345678-1234-1234-1234-123456789012",
       client_id="87654321-4321-4321-4321-210987654321",
       issuer="https://sts.windows.net/12345678-1234-1234-1234-123456789012/",
   )

   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=EntraIdProvider(settings=entra_settings),
   )

   @app.get("/user/profile", dependencies=[Depends(require_user())])
   async def get_user_profile(request):
       user = request.state.current_user
       return {
           "user_id": user.id,
           "name": user.name,
           "email": user.email,
           "tenant": user.tenant_id,
           "roles": user.roles,
       }

   @app.get("/admin/users", dependencies=[Depends(require_groups(["Administrators"]))])
   async def list_users(request):
       # Only users in the "Administrators" group can access this endpoint
       return {"message": "Admin access granted"}

Multi-tenant SaaS Application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   # Multi-tenant configuration
   entra_settings = EntraIdProviderSettings(
       tenant_id="common",
       client_id="your-saas-app-id",
       issuer="https://sts.windows.net/",
       validate_tenant=False,
   )

   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=EntraIdProvider(settings=entra_settings),
   )

   @app.get("/tenant/info", dependencies=[Depends(require_user())])
   async def get_tenant_info(request):
       user = request.state.current_user
       return {
           "tenant_id": user.tenant_id,
           "user_count": await get_tenant_user_count(user.tenant_id),
           "subscription": await get_tenant_subscription(user.tenant_id),
       }

Token Acquisition
----------------

Client-side Token Acquisition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

JavaScript/TypeScript example for acquiring tokens:

.. code-block:: javascript

   import { PublicClientApplication } from "@azure/msal-browser";

   const msalConfig = {
     auth: {
       clientId: "your-application-id",
       authority: "https://login.microsoftonline.com/your-tenant-id",
       redirectUri: "http://localhost:3000"
     }
   };

   const msalInstance = new PublicClientApplication(msalConfig);

   // Acquire token
   const tokenRequest = {
     scopes: ["api://your-application-id/access_as_user"],
   };

   const response = await msalInstance.acquireTokenSilent(tokenRequest);
   const accessToken = response.accessToken;

   // Use token in API calls
   const apiResponse = await fetch("/api/protected", {
     headers: {
       "Authorization": `Bearer ${accessToken}`
     }
   });

Server-side Token Acquisition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Python example using MSAL:

.. code-block:: python

   from msal import ConfidentialClientApplication

   app = ConfidentialClientApplication(
       client_id="your-application-id",
       client_credential="your-client-secret",
       authority="https://login.microsoftonline.com/your-tenant-id"
   )

   # Acquire token for API access
   result = app.acquire_token_for_client(
       scopes=["https://graph.microsoft.com/.default"]
   )

   if "access_token" in result:
       access_token = result["access_token"]

Error Handling
--------------

Entra ID Specific Errors
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from auth_middleware.exceptions import AuthenticationError
   from fastapi import HTTPException

   @app.exception_handler(AuthenticationError)
   async def entra_auth_error_handler(request, exc):
       error_details = {
           "error": "authentication_failed",
           "error_description": str(exc),
           "tenant_hint": "Use your organization account"
       }
       
       if "tenant" in str(exc).lower():
           error_details["error_uri"] = "https://docs.microsoft.com/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant"
       
       return JSONResponse(
           status_code=401,
           content=error_details
       )

Best Practices
--------------

Security Recommendations
~~~~~~~~~~~~~~~~~~~~~~~~

1. **Validate Tenant**: Always validate the tenant ID in single-tenant applications
2. **Scope Validation**: Validate that tokens contain required scopes
3. **Group Membership**: Use Azure AD groups for authorization
4. **Token Caching**: Implement proper token caching on the client side
5. **Certificate Authentication**: Use certificates instead of client secrets for production

Performance Optimization
~~~~~~~~~~~~~~~~~~~~~~~

1. **Key Caching**: The provider automatically caches Azure's public keys
2. **Connection Pooling**: Use HTTP connection pooling for JWKS endpoints
3. **Token Validation**: Validate tokens locally to reduce Azure AD calls

Troubleshooting
--------------

Common Issues
~~~~~~~~~~~~

**Invalid Issuer**
   Ensure the issuer in your configuration matches the token's 'iss' claim

**Audience Mismatch**
   Verify that the client_id matches the token's 'aud' claim

**Tenant Validation Failed**
   Check that the tenant_id matches the token's 'tid' claim

**Groups Not Available**
   Ensure the application has the required Graph API permissions for group claims

API Reference
-------------

.. automodule:: auth_middleware.providers.authn.entra_id_provider
   :members:

.. automodule:: auth_middleware.providers.authn.entra_id_provider_settings
   :members:

For more information about other authentication providers, see:

* :doc:`cognito_provider` - AWS Cognito integration
* :doc:`jwt_auth_provider` - Generic JWT provider
