.. _permissions-provider:

Permissions Provider
====================

The Permissions Provider system in auth-middleware enables fine-grained authorization by retrieving user permissions from various sources. This allows you to implement detailed access control beyond simple role-based systems.

Overview
========

Permissions providers implement the ``PermissionsProvider`` interface and are responsible for fetching user permissions based on JWT token information. The middleware uses these permissions for granular access control to specific resources and actions.

.. note::
   Permissions provide more granular control than groups. While groups typically represent roles (admin, user), permissions represent specific actions (read:posts, write:comments, delete:users).

Built-in Providers
==================

SqlPermissionsProvider
----------------------

Retrieves permissions from a SQL database using SQLAlchemy.

**Features:**
- Stores user permissions in database
- Supports multiple database backends (PostgreSQL, MySQL, SQLite)
- Async database operations
- Configurable database connection

**Database Schema:**

.. code-block:: sql

   CREATE TABLE authz_permissions (
       id VARCHAR(27) PRIMARY KEY,
       username VARCHAR(500) NOT NULL,
       permission VARCHAR(100) NOT NULL
   );

   CREATE INDEX idx_authz_permissions_username ON authz_permissions(username);

**Usage:**

.. code-block:: python

   from auth_middleware.providers.authz.sql_permissions_provider import SqlPermissionsProvider
   from auth_middleware.providers.authz.async_database import AsyncDatabase
   from auth_middleware.providers.authz.async_database_settings import AsyncDatabaseSettings

   # Configure database connection
   db_settings = AsyncDatabaseSettings(
       database_url="postgresql+asyncpg://user:pass@localhost/mydb"
   )
   AsyncDatabase.configure(db_settings)

   # Configure the permissions provider
   permissions_provider = SqlPermissionsProvider()

   # Add middleware with permissions provider
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=auth_provider,
       permissions_provider=permissions_provider,
   )

**Managing Permissions:**

Add permissions to users by inserting records:

.. code-block:: python

   from auth_middleware.providers.authz.sql_permissions_provider import PermissionsModel
   from auth_middleware.providers.authz.async_database import AsyncDatabase

   async def grant_permission(username: str, permission: str):
       async with AsyncDatabase.get_session() as session:
           permission_record = PermissionsModel(username=username, permission=permission)
           session.add(permission_record)
           await session.commit()

   async def revoke_permission(username: str, permission: str):
       async with AsyncDatabase.get_session() as session:
           query = select(PermissionsModel).filter(
               PermissionsModel.username == username,
               PermissionsModel.permission == permission
           )
           result = await session.execute(query)
           permission_record = result.scalar_one_or_none()
           
           if permission_record:
               await session.delete(permission_record)
               await session.commit()

   # Example usage
   await grant_permission("john.doe", "read:posts")
   await grant_permission("john.doe", "write:posts")
   await grant_permission("admin", "delete:posts")

Using Permissions in Your Application
=====================================

Once configured, permissions are automatically available in your endpoints:

.. code-block:: python

   from fastapi import Depends, FastAPI
   from auth_middleware.functions import require_permissions, get_current_user
   from auth_middleware.types.user import User

   app = FastAPI()

   @app.get("/posts")
   async def read_posts(user: User = Depends(require_permissions("read:posts"))):
       return {"posts": [...]}

   @app.post("/posts")
   async def create_post(user: User = Depends(require_permissions("write:posts"))):
       return {"message": "Post created"}

   @app.delete("/posts/{post_id}")
   async def delete_post(
       post_id: int,
       user: User = Depends(require_permissions("delete:posts"))
   ):
       return {"message": f"Post {post_id} deleted"}

   @app.get("/user-permissions")
   async def user_permissions(user: User = Depends(get_current_user())):
       # Access permissions directly
       permissions = await user.permissions
       return {"username": user.username, "permissions": permissions}

   @app.get("/admin-posts")
   async def admin_posts(
       user: User = Depends(require_permissions(["read:posts", "admin:posts"]))
   ):
       return {"message": "Admin access to posts"}

Permission Patterns
===================

**Common Permission Formats:**

.. code-block:: python

   # Resource-based permissions
   "read:posts"
   "write:posts"
   "delete:posts"
   
   # Action-based permissions
   "create:user"
   "update:user"
   "delete:user"
   
   # Hierarchical permissions
   "admin:system"
   "admin:users"
   "admin:posts"
   
   # Fine-grained permissions
   "read:posts:published"
   "write:posts:draft"
   "approve:posts:pending"

**Permission Inheritance:**

.. code-block:: python

   class HierarchicalPermissionsProvider(PermissionsProvider):
       """Permissions provider with inheritance support."""
       
       PERMISSION_HIERARCHY = {
           "admin": ["admin:*"],
           "admin:posts": ["read:posts", "write:posts", "delete:posts"],
           "admin:users": ["read:users", "write:users", "delete:users"],
           "editor": ["read:posts", "write:posts"],
           "viewer": ["read:posts"]
       }
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions with hierarchy resolution."""
           # Get base permissions
           base_permissions = await self._fetch_base_permissions(token)
           
           # Expand hierarchical permissions
           expanded_permissions = set()
           for permission in base_permissions:
               expanded_permissions.add(permission)
               
               # Add inherited permissions
               if permission in self.PERMISSION_HIERARCHY:
                   expanded_permissions.update(self.PERMISSION_HIERARCHY[permission])
           
           # Handle wildcard permissions
           final_permissions = []
           for permission in expanded_permissions:
               if permission.endswith(":*"):
                   # Grant all permissions for this resource
                   resource = permission[:-2]
                   final_permissions.extend(self._get_all_permissions_for_resource(resource))
               else:
                   final_permissions.append(permission)
           
           return list(set(final_permissions))

Custom Permissions Provider
===========================

Create custom permissions providers by implementing the ``PermissionsProvider`` interface:

**Basic Implementation:**

.. code-block:: python

   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class CustomPermissionsProvider(PermissionsProvider):
       """Custom permissions provider implementation."""
       
       def __init__(self, api_client):
           self.api_client = api_client
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions from custom source."""
           username = token.claims.get("username")
           
           # Implement your custom logic here
           permissions = await self.api_client.get_user_permissions(username)
           
           return permissions

**Redis Permissions Provider:**

.. code-block:: python

   import json
   import redis.asyncio as redis
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class RedisPermissionsProvider(PermissionsProvider):
       """Permissions provider using Redis for storage."""
       
       def __init__(self, redis_url: str = "redis://localhost:6379"):
           self.redis_url = redis_url
           self._redis = None
       
       async def _get_redis(self):
           if self._redis is None:
               self._redis = redis.from_url(self.redis_url)
           return self._redis
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions from Redis."""
           username = token.claims.get("username")
           if not username:
               return []
           
           redis_client = await self._get_redis()
           
           # Get direct permissions
           direct_permissions = await redis_client.smembers(f"user_permissions:{username}")
           
           # Get role-based permissions
           user_roles = await redis_client.smembers(f"user_roles:{username}")
           role_permissions = []
           
           for role in user_roles:
               role_perms = await redis_client.smembers(f"role_permissions:{role}")
               role_permissions.extend(role_perms)
           
           # Combine and deduplicate
           all_permissions = list(set(direct_permissions) | set(role_permissions))
           
           return [perm.decode() if isinstance(perm, bytes) else perm for perm in all_permissions]

**JWT Claims-based Provider:**

.. code-block:: python

   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class JwtPermissionsProvider(PermissionsProvider):
       """Extract permissions directly from JWT claims."""
       
       def __init__(self, permissions_claim: str = "permissions"):
           self.permissions_claim = permissions_claim
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Extract permissions from JWT claims."""
           permissions = token.claims.get(self.permissions_claim, [])
           
           # Handle different claim formats
           if isinstance(permissions, str):
               # Space-separated permissions
               return permissions.split()
           elif isinstance(permissions, list):
               # List of permissions
               return permissions
           else:
               return []

**API-based Permissions Provider:**

.. code-block:: python

   import httpx
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class ApiPermissionsProvider(PermissionsProvider):
       """Permissions provider using external API."""
       
       def __init__(self, api_base_url: str, api_key: str, timeout: int = 10):
           self.api_base_url = api_base_url
           self.api_key = api_key
           self.timeout = timeout
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions from external API."""
           username = token.claims.get("username")
           user_id = token.claims.get("sub")
           
           if not username and not user_id:
               return []
           
           identifier = username or user_id
           
           async with httpx.AsyncClient(timeout=self.timeout) as client:
               try:
                   response = await client.get(
                       f"{self.api_base_url}/users/{identifier}/permissions",
                       headers={"Authorization": f"Bearer {self.api_key}"}
                   )
                   response.raise_for_status()
                   
                   data = response.json()
                   return data.get("permissions", [])
               
               except httpx.HTTPError as e:
                   # Log error and return empty permissions
                   logger.error(f"Failed to fetch permissions: {e}")
                   return []

**File-based Permissions Provider:**

.. code-block:: python

   import json
   import os
   from pathlib import Path
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class FilePermissionsProvider(PermissionsProvider):
       """Permissions provider using JSON file storage."""
       
       def __init__(self, permissions_file: str = "permissions.json"):
           self.permissions_file = Path(permissions_file)
           self._permissions_cache = None
           self._last_modified = None
       
       async def _load_permissions(self):
           """Load permissions from file with caching."""
           if not self.permissions_file.exists():
               return {}
           
           current_modified = self.permissions_file.stat().st_mtime
           
           if (self._permissions_cache is None or 
               self._last_modified != current_modified):
               
               with open(self.permissions_file) as f:
                   self._permissions_cache = json.load(f)
               self._last_modified = current_modified
           
           return self._permissions_cache
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions from JSON file."""
           username = token.claims.get("username")
           if not username:
               return []
           
           permissions_data = await self._load_permissions()
           
           # Get direct user permissions
           user_permissions = permissions_data.get("users", {}).get(username, [])
           
           # Get role-based permissions
           user_roles = permissions_data.get("user_roles", {}).get(username, [])
           role_permissions = []
           
           for role in user_roles:
               role_perms = permissions_data.get("roles", {}).get(role, [])
               role_permissions.extend(role_perms)
           
           # Combine and deduplicate
           all_permissions = list(set(user_permissions + role_permissions))
           
           return all_permissions

**Example permissions.json file:**

.. code-block:: json

   {
     "users": {
       "admin": ["admin:*"],
       "john.doe": ["read:posts", "write:posts"]
     },
     "roles": {
       "editor": ["read:posts", "write:posts", "edit:posts"],
       "viewer": ["read:posts"],
       "admin": ["admin:*"]
     },
     "user_roles": {
       "john.doe": ["editor"],
       "jane.smith": ["viewer"],
       "admin": ["admin"]
     }
   }

Advanced Features
=================

**Conditional Permissions:**

.. code-block:: python

   class ConditionalPermissionsProvider(PermissionsProvider):
       """Permissions provider with conditional logic."""
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions with conditional logic."""
           username = token.claims.get("username")
           permissions = await self._get_base_permissions(username)
           
           # Add time-based permissions
           current_hour = datetime.now().hour
           if 9 <= current_hour <= 17:  # Business hours
               permissions.append("business_hours:access")
           
           # Add location-based permissions (from token claims)
           location = token.claims.get("location")
           if location == "headquarters":
               permissions.append("onsite:access")
           
           # Add temporary permissions
           temp_permissions = await self._get_temporary_permissions(username)
           permissions.extend(temp_permissions)
           
           return permissions

**Cached Permissions Provider:**

.. code-block:: python

   import asyncio
   from datetime import datetime, timedelta
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class CachedPermissionsProvider(PermissionsProvider):
       """Permissions provider with caching support."""
       
       def __init__(self, base_provider: PermissionsProvider, cache_ttl: int = 300):
           self.base_provider = base_provider
           self.cache_ttl = cache_ttl
           self._cache = {}
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions with caching."""
           username = token.claims.get("username")
           cache_key = f"permissions:{username}"
           
           # Check cache
           if cache_key in self._cache:
               cached_data, timestamp = self._cache[cache_key]
               if datetime.now() - timestamp < timedelta(seconds=self.cache_ttl):
                   return cached_data
           
           # Fetch from base provider
           permissions = await self.base_provider.fetch_permissions(token)
           
           # Cache result
           self._cache[cache_key] = (permissions, datetime.now())
           
           return permissions
       
       def clear_cache(self, username: str = None):
           """Clear cache for specific user or all users."""
           if username:
               cache_key = f"permissions:{username}"
               self._cache.pop(cache_key, None)
           else:
               self._cache.clear()

Permission Management
====================

**Permission Management API:**

.. code-block:: python

   from fastapi import FastAPI, Depends, HTTPException
   from pydantic import BaseModel
   from auth_middleware.functions import require_permissions

   app = FastAPI()

   class PermissionRequest(BaseModel):
       username: str
       permission: str

   @app.post("/api/permissions/grant")
   async def grant_permission(
       request: PermissionRequest,
       admin: User = Depends(require_permissions("admin:permissions"))
   ):
       """Grant permission to user."""
       await grant_permission(request.username, request.permission)
       return {"message": f"Permission {request.permission} granted to {request.username}"}

   @app.post("/api/permissions/revoke")
   async def revoke_permission(
       request: PermissionRequest,
       admin: User = Depends(require_permissions("admin:permissions"))
   ):
       """Revoke permission from user."""
       await revoke_permission(request.username, request.permission)
       return {"message": f"Permission {request.permission} revoked from {request.username}"}

   @app.get("/api/permissions/{username}")
   async def get_user_permissions(
       username: str,
       admin: User = Depends(require_permissions("admin:permissions"))
   ):
       """Get all permissions for a user."""
       # This would need to be implemented based on your provider
       permissions = await get_user_permissions_from_db(username)
       return {"username": username, "permissions": permissions}

Testing Permissions Providers
=============================

**Unit Testing:**

.. code-block:: python

   import pytest
   from unittest.mock import AsyncMock
   from auth_middleware.types.jwt import JWTAuthorizationCredentials
   from your_app.providers import CustomPermissionsProvider

   @pytest.mark.asyncio
   async def test_custom_permissions_provider():
       # Setup
       mock_api_client = AsyncMock()
       mock_api_client.get_user_permissions.return_value = ["read:posts", "write:posts"]
       
       provider = CustomPermissionsProvider(mock_api_client)
       
       # Create test token
       token = JWTAuthorizationCredentials(
           jwt_token="test_token",
           header={"alg": "HS256"},
           signature="signature",
           message="message",
           claims={"username": "testuser"}
       )
       
       # Test
       permissions = await provider.fetch_permissions(token)
       
       # Assertions
       assert permissions == ["read:posts", "write:posts"]
       mock_api_client.get_user_permissions.assert_called_once_with("testuser")

**Integration Testing:**

.. code-block:: python

   from fastapi.testclient import TestClient
   from your_app.main import app

   def test_permissions_authorization():
       client = TestClient(app)
       
       # Test with sufficient permissions
       user_token = "valid_jwt_with_read_posts_permission"
       response = client.get(
           "/posts",
           headers={"Authorization": f"Bearer {user_token}"}
       )
       assert response.status_code == 200
       
       # Test with insufficient permissions
       limited_token = "valid_jwt_without_read_posts_permission"
       response = client.get(
           "/posts",
           headers={"Authorization": f"Bearer {limited_token}"}
       )
       assert response.status_code == 403

Best Practices
==============

**Security Considerations:**

1. **Principle of Least Privilege**: Grant minimum necessary permissions
2. **Regular Audits**: Regularly review and clean up permissions
3. **Permission Expiration**: Implement time-based permission expiration
4. **Audit Logging**: Log all permission grants and revocations

**Performance Optimization:**

1. **Caching**: Cache frequently accessed permissions
2. **Batch Operations**: Batch permission checks when possible
3. **Database Indexes**: Ensure proper indexing on username columns
4. **Connection Pooling**: Use database connection pooling

**Error Handling:**

.. code-block:: python

   class RobustPermissionsProvider(PermissionsProvider):
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           try:
               return await self._fetch_permissions_internal(token)
           except Exception as e:
               logger.error(f"Failed to fetch permissions: {e}")
               # Return minimal permissions or raise exception
               return []  # Or raise an exception based on your security model

Troubleshooting
===============

**Common Issues:**

1. **Permissions Not Loading**
   
   - Check database connectivity
   - Verify permission format and naming
   - Ensure proper provider configuration

2. **Performance Issues**
   
   - Implement caching for frequently accessed permissions
   - Check database query performance
   - Monitor external API response times

3. **Authorization Failures**
   
   - Verify permission names match exactly
   - Check case sensitivity
   - Ensure permissions are properly granted

API Reference
=============

.. autoclass:: auth_middleware.providers.authz.permissions_provider.PermissionsProvider
   :members:

.. autoclass:: auth_middleware.providers.authz.sql_permissions_provider.SqlPermissionsProvider
   :members:

See Also
========

- :doc:`groups-provider` - For role-based authorization
- :doc:`../functions` - For using permissions in endpoint dependencies
- :doc:`../middleware-configuration` - For middleware setup with permissions providers
