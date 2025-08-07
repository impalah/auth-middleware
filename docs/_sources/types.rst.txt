Type Definitions
================

This module contains type definitions and data structures used throughout the auth-middleware library. These types provide type safety and clear interfaces for authentication and authorization components.

Core Types
----------

User Types
~~~~~~~~~~

The library defines several user-related types to represent authenticated users:

.. code-block:: python

   from typing import List, Optional, Dict, Any
   from dataclasses import dataclass

   @dataclass
   class User:
       """Represents an authenticated user."""
       id: str
       name: str
       email: str
       groups: List[str] = None
       permissions: List[str] = None
       extra: Dict[str, Any] = None

Provider Types
~~~~~~~~~~~~~

Authentication providers implement the following interfaces:

.. code-block:: python

   from abc import ABC, abstractmethod
   from typing import Protocol

   class AuthenticationProvider(Protocol):
       """Protocol for authentication providers."""
       
       async def validate_token(self, token: str) -> Dict[str, Any]:
           """Validate a token and return user information."""
           ...
       
       async def get_user_info(self, token_data: Dict[str, Any]) -> User:
           """Extract user information from token data."""
           ...

Configuration Types
~~~~~~~~~~~~~~~~~~

Provider settings and configuration types:

.. code-block:: python

   from pydantic import BaseModel
   from typing import Optional

   class ProviderSettings(BaseModel):
       """Base settings for authentication providers."""
       
       class Config:
           extra = "forbid"  # Prevent additional fields

   class JWTProviderSettings(ProviderSettings):
       """Settings for JWT authentication provider."""
       secret_key: str
       algorithm: str = "HS256"
       issuer: Optional[str] = None
       audience: Optional[str] = None
       verify_signature: bool = True
       verify_exp: bool = True
       verify_iat: bool = True
       leeway: int = 0

Token Types
----------

JWT Token Structure
~~~~~~~~~~~~~~~~~~

Standard JWT token claims structure:

.. code-block:: python

   from typing import Union, List, Dict, Any
   from datetime import datetime

   class JWTClaims:
       """Standard JWT claims."""
       
       # Standard claims
       iss: Optional[str] = None      # Issuer
       sub: Optional[str] = None      # Subject (user ID)
       aud: Union[str, List[str]] = None  # Audience
       exp: Optional[datetime] = None  # Expiration time
       iat: Optional[datetime] = None  # Issued at
       nbf: Optional[datetime] = None  # Not before
       jti: Optional[str] = None      # JWT ID
       
       # Custom claims
       name: Optional[str] = None
       email: Optional[str] = None
       groups: List[str] = []
       permissions: List[str] = []
       custom_claims: Dict[str, Any] = {}

Authentication Context
---------------------

Request Context Types
~~~~~~~~~~~~~~~~~~~~

Types for managing authentication context in requests:

.. code-block:: python

   from starlette.requests import Request
   from typing import Optional

   class AuthenticatedRequest(Request):
       """Extended request with authentication context."""
       
       @property
       def current_user(self) -> Optional[User]:
           """Get the current authenticated user."""
           return getattr(self.state, 'current_user', None)
       
       @property
       def auth_token(self) -> Optional[str]:
           """Get the authentication token."""
           return getattr(self.state, 'auth_token', None)
       
       @property
       def is_authenticated(self) -> bool:
           """Check if request is authenticated."""
           return self.current_user is not None

Middleware Types
~~~~~~~~~~~~~~~

Types for middleware configuration:

.. code-block:: python

   from enum import Enum
   from typing import Callable, Awaitable

   class AuthMode(Enum):
       """Authentication modes."""
       REQUIRED = "required"      # Authentication required for all endpoints
       OPTIONAL = "optional"      # Authentication optional
       DISABLED = "disabled"      # Authentication disabled

   class AuthMiddlewareConfig:
       """Configuration for authentication middleware."""
       
       auth_provider: AuthenticationProvider
       auth_mode: AuthMode = AuthMode.REQUIRED
       excluded_paths: List[str] = []
       included_paths: List[str] = []
       token_header: str = "Authorization"
       token_prefix: str = "Bearer"

Exception Types
--------------

Error and Exception Types
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from typing import Optional, List

   class AuthError:
       """Base authentication error."""
       
       def __init__(
           self,
           message: str,
           error_code: Optional[str] = None,
           details: Optional[Dict[str, Any]] = None
       ):
           self.message = message
           self.error_code = error_code
           self.details = details or {}

   class ValidationError(AuthError):
       """Token validation error."""
       
       def __init__(
           self,
           message: str,
           token: Optional[str] = None,
           claims: Optional[Dict[str, Any]] = None
       ):
           super().__init__(message)
           self.token = token
           self.claims = claims

Provider-Specific Types
----------------------

AWS Cognito Types
~~~~~~~~~~~~~~~~

.. code-block:: python

   class CognitoUser(User):
       """Cognito-specific user representation."""
       
       cognito_username: str
       user_pool_id: str
       client_id: str
       token_use: str  # 'access' or 'id'
       cognito_groups: List[str] = []
       custom_attributes: Dict[str, str] = {}

Azure Entra ID Types
~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   class EntraIdUser(User):
       """Azure Entra ID user representation."""
       
       object_id: str
       tenant_id: str
       app_id: str
       roles: List[str] = []
       scopes: List[str] = []
       upn: Optional[str] = None  # User Principal Name

Validation Types
---------------

Validation Rules
~~~~~~~~~~~~~~~

.. code-block:: python

   from typing import Callable, Any

   ValidationRule = Callable[[Any], bool]

   class PermissionRule:
       """Permission validation rule."""
       
       def __init__(
           self,
           required_permissions: List[str],
           operation: str = "any"  # "any" or "all"
       ):
           self.required_permissions = required_permissions
           self.operation = operation
       
       def validate(self, user_permissions: List[str]) -> bool:
           if self.operation == "all":
               return all(perm in user_permissions for perm in self.required_permissions)
           else:  # "any"
               return any(perm in user_permissions for perm in self.required_permissions)

   class GroupRule:
       """Group membership validation rule."""
       
       def __init__(
           self,
           required_groups: List[str],
           operation: str = "any"
       ):
           self.required_groups = required_groups
           self.operation = operation
       
       def validate(self, user_groups: List[str]) -> bool:
           if self.operation == "all":
               return all(group in user_groups for group in self.required_groups)
           else:  # "any"
               return any(group in user_groups for group in self.required_groups)

Usage Examples
--------------

Type Hints in Application Code
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from fastapi import FastAPI, Depends
   from auth_middleware.types import User, AuthenticatedRequest
   from auth_middleware import get_current_user

   app = FastAPI()

   @app.get("/profile")
   async def get_profile(
       request: AuthenticatedRequest,
       user: User = Depends(get_current_user)
   ) -> Dict[str, Any]:
       return {
           "user_id": user.id,
           "name": user.name,
           "email": user.email,
           "groups": user.groups,
           "is_authenticated": request.is_authenticated
       }

Custom Provider Implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: python

   from auth_middleware.types import AuthenticationProvider, User, ProviderSettings

   class CustomProviderSettings(ProviderSettings):
       api_key: str
       base_url: str = "https://api.example.com"

   class CustomProvider(AuthenticationProvider):
       def __init__(self, settings: CustomProviderSettings):
           self.settings = settings
       
       async def validate_token(self, token: str) -> Dict[str, Any]:
           # Custom validation logic
           ...
       
       async def get_user_info(self, token_data: Dict[str, Any]) -> User:
           # Extract user information
           return User(
               id=token_data["user_id"],
               name=token_data["name"],
               email=token_data["email"],
               groups=token_data.get("groups", [])
           )

API Reference
-------------

.. automodule:: auth_middleware.types
   :members:
