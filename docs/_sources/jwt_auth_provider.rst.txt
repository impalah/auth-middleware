JWT Authentication Provider
===========================

The JWT Authentication Provider is a generic provider that can validate JWT tokens signed with various algorithms. This provider is useful when you have your own JWT token issuing service or need to integrate with custom authentication systems.

Overview
--------

The JWT provider supports:

* **Multiple Algorithms**: HS256, HS384, HS512, RS256, RS384, RS512, and more
* **Custom Claims**: Flexible claim mapping for user information
* **Secret Management**: Support for both symmetric and asymmetric keys
* **Claim Validation**: Standard JWT claim validation (exp, iat, iss, aud)
* **Custom Validation**: Extensible validation logic

Configuration
-------------

Basic Configuration
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.authn.jwt_provider import JWTProvider
   from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings

   # Configure JWT settings
   jwt_settings = JWTProviderSettings(
       secret_key="your-secret-key",
       algorithm="HS256",
       issuer="your-issuer",
       audience="your-audience",
   )

   # Create JWT provider
   jwt_provider = JWTProvider(settings=jwt_settings)

   # Add to FastAPI application
   app.add_middleware(JwtAuthMiddleware, auth_provider=jwt_provider)

Environment-based Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For production deployments, use environment variables:

.. code-block:: python

   import os
   from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings

   def create_jwt_settings():
       return JWTProviderSettings(
           secret_key=os.getenv("JWT_SECRET_KEY"),
           algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
           issuer=os.getenv("JWT_ISSUER"),
           audience=os.getenv("JWT_AUDIENCE"),
           verify_signature=os.getenv("JWT_VERIFY_SIGNATURE", "true").lower() == "true",
           verify_exp=os.getenv("JWT_VERIFY_EXP", "true").lower() == "true",
           verify_iat=os.getenv("JWT_VERIFY_IAT", "true").lower() == "true",
       )

Token Structure
--------------

Expected JWT Claims
~~~~~~~~~~~~~~~~~~

The JWT provider expects the following standard claims:

.. code-block:: json

   {
     "sub": "user123",                    // Subject (user ID)
     "name": "John Doe",                  // User name
     "email": "john@example.com",         // User email
     "groups": ["user", "admin"],         // User groups (optional)
     "permissions": ["read", "write"],    // User permissions (optional)
     "iss": "your-issuer",               // Issuer
     "aud": "your-audience",             // Audience
     "exp": 1640995200,                  // Expiration timestamp
     "iat": 1640908800,                  // Issued at timestamp
     "custom_claim": "custom_value"      // Custom claims
   }

Custom Claim Mapping
~~~~~~~~~~~~~~~~~~~

You can customize how claims are mapped to user properties:

.. code-block:: python

   class CustomJWTProvider(JWTProvider):
       def extract_user_info(self, decoded_token: dict) -> dict:
           return {
               "id": decoded_token.get("user_id"),        # Custom user ID field
               "name": decoded_token.get("full_name"),    # Custom name field
               "email": decoded_token.get("email_addr"),  # Custom email field
               "groups": decoded_token.get("roles", []),  # Custom groups field
               "permissions": decoded_token.get("perms", []),
               "raw_token": decoded_token,
           }

Integration Examples
-------------------

With Custom Token Service
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from fastapi import FastAPI, Depends
   from auth_middleware import JwtAuthMiddleware, require_user
   from auth_middleware.providers.authn.jwt_provider import JWTProvider
   from auth_middleware.providers.authn.jwt_provider_settings import JWTProviderSettings

   app = FastAPI(title="Custom JWT API")

   # JWT configuration for your custom token service
   jwt_settings = JWTProviderSettings(
       secret_key="your-hmac-secret-key",
       algorithm="HS256",
       issuer="your-auth-service",
       audience="your-api",
       verify_exp=True,
       leeway=30,  # 30 seconds clock skew allowance
   )

   # Setup middleware
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=JWTProvider(settings=jwt_settings),
   )

   @app.get("/profile", dependencies=[Depends(require_user())])
   async def get_profile(request):
       user = request.state.current_user
       return {
           "user_id": user.id,
           "name": user.name,
           "email": user.email,
           "groups": user.groups,
       }

Best Practices
--------------

Security Recommendations
~~~~~~~~~~~~~~~~~~~~~~~~

1. **Use Strong Keys**: Use cryptographically secure random keys
2. **Short Expiration**: Use reasonable token expiration times
3. **Rotate Keys**: Regularly rotate signing keys
4. **Validate All Claims**: Don't skip important claim validations
5. **Use HTTPS**: Always use HTTPS to protect tokens in transit

API Reference
-------------

.. automodule:: auth_middleware.providers.authn.jwt_provider
   :members:

.. automodule:: auth_middleware.providers.authn.jwt_provider_settings
   :members:
