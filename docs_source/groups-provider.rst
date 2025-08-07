.. _groups-provider:

Groups Provider
===============

The Groups Provider system in auth-middleware allows you to implement custom authorization logic by retrieving user groups from various sources. This enables flexible role-based access control (RBAC) in your application.

Overview
========

Groups providers implement the ``GroupsProvider`` interface and are responsible for fetching user groups based on JWT token information. The middleware uses these groups to determine user permissions and access levels.

.. note::
   Groups are typically used for role-based authorization, while permissions provide more granular access control. Both can be used together for comprehensive authorization systems.

Built-in Providers
==================

CognitoGroupsProvider
--------------------

Extracts groups directly from AWS Cognito JWT tokens.

**Features:**
- Reads groups from ``cognito:groups`` claim
- Fallback to ``scope`` claim for single group scenarios
- No external database queries required
- Zero-latency group resolution

**Usage:**

.. code-block:: python

   from auth_middleware.providers.authz.cognito_groups_provider import CognitoGroupsProvider
   from auth_middleware.jwt_auth_middleware import JwtAuthMiddleware
   from auth_middleware.providers.authn.cognito_provider import CognitoProvider

   # Configure the authentication provider
   auth_provider = CognitoProvider(settings=auth_settings)
   
   # Configure the groups provider
   groups_provider = CognitoGroupsProvider()

   # Add middleware with groups provider
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=auth_provider,
       groups_provider=groups_provider,
   )

**Token Format:**

The provider expects JWT tokens with group information in one of these formats:

.. code-block:: json

   {
     "sub": "user123",
     "username": "john.doe",
     "cognito:groups": ["admin", "user", "moderator"],
     "exp": 1234567890
   }

Or for single scope scenarios:

.. code-block:: json

   {
     "sub": "user123", 
     "username": "john.doe",
     "scope": "api/admin",
     "exp": 1234567890
   }

SqlGroupsProvider
-----------------

Retrieves groups from a SQL database using SQLAlchemy.

**Features:**
- Stores group memberships in database
- Supports multiple database backends (PostgreSQL, MySQL, SQLite)
- Async database operations
- Configurable database connection

**Database Schema:**

.. code-block:: sql

   CREATE TABLE authz_groups (
       id VARCHAR(27) PRIMARY KEY,
       username VARCHAR(500) NOT NULL,
       group_name VARCHAR(100) NOT NULL
   );

   CREATE INDEX idx_authz_groups_username ON authz_groups(username);

**Usage:**

.. code-block:: python

   from auth_middleware.providers.authz.sql_groups_provider import SqlGroupsProvider
   from auth_middleware.providers.authz.async_database import AsyncDatabase
   from auth_middleware.providers.authz.async_database_settings import AsyncDatabaseSettings

   # Configure database connection
   db_settings = AsyncDatabaseSettings(
       database_url="postgresql+asyncpg://user:pass@localhost/mydb"
   )
   AsyncDatabase.configure(db_settings)

   # Configure the groups provider
   groups_provider = SqlGroupsProvider()

   # Add middleware with groups provider
   app.add_middleware(
       JwtAuthMiddleware,
       auth_provider=auth_provider,
       groups_provider=groups_provider,
   )

**Managing Groups:**

Add users to groups by inserting records:

.. code-block:: python

   from auth_middleware.providers.authz.sql_groups_provider import GroupsModel
   from auth_middleware.providers.authz.async_database import AsyncDatabase

   async def add_user_to_group(username: str, group: str):
       async with AsyncDatabase.get_session() as session:
           group_record = GroupsModel(username=username, group=group)
           session.add(group_record)
           await session.commit()

   # Example usage
   await add_user_to_group("john.doe", "admin")
   await add_user_to_group("john.doe", "user")

Using Groups in Your Application
=================================

Once configured, groups are automatically available in your endpoints through the user object:

.. code-block:: python

   from fastapi import Depends, FastAPI
   from auth_middleware.functions import require_groups, get_current_user
   from auth_middleware.types.user import User

   app = FastAPI()

   @app.get("/admin-only")
   async def admin_endpoint(user: User = Depends(require_groups("admin"))):
       return {"message": f"Hello admin {user.username}"}

   @app.get("/user-info")
   async def user_info(user: User = Depends(get_current_user())):
       # Access groups directly
       groups = await user.groups
       return {"username": user.username, "groups": groups}

   @app.get("/multi-role")
   async def multi_role(user: User = Depends(require_groups(["admin", "moderator"]))):
       return {"message": "Admin or moderator access"}

Custom Groups Provider
======================

You can create custom groups providers by implementing the ``GroupsProvider`` interface:

**Basic Implementation:**

.. code-block:: python

   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class CustomGroupsProvider(GroupsProvider):
       """Custom groups provider implementation."""
       
       def __init__(self, api_client):
           self.api_client = api_client
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups from custom source."""
           username = token.claims.get("username")
           
           # Implement your custom logic here
           groups = await self.api_client.get_user_groups(username)
           
           return groups

**Advanced Example - Redis Groups Provider:**

.. code-block:: python

   import json
   import redis.asyncio as redis
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class RedisGroupsProvider(GroupsProvider):
       """Groups provider using Redis for storage."""
       
       def __init__(self, redis_url: str = "redis://localhost:6379"):
           self.redis_url = redis_url
           self._redis = None
       
       async def _get_redis(self):
           if self._redis is None:
               self._redis = redis.from_url(self.redis_url)
           return self._redis
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups from Redis."""
           username = token.claims.get("username")
           if not username:
               return []
           
           redis_client = await self._get_redis()
           
           # Get groups from Redis hash
           groups_data = await redis_client.hget("user_groups", username)
           
           if groups_data:
               return json.loads(groups_data)
           
           return []
       
       async def close(self):
           """Clean up Redis connection."""
           if self._redis:
               await self._redis.close()

   # Usage
   groups_provider = RedisGroupsProvider("redis://localhost:6379")

**LDAP/Active Directory Groups Provider:**

.. code-block:: python

   import ldap3
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class LdapGroupsProvider(GroupsProvider):
       """Groups provider using LDAP/Active Directory."""
       
       def __init__(self, server_url: str, base_dn: str, bind_user: str, bind_password: str):
           self.server_url = server_url
           self.base_dn = base_dn
           self.bind_user = bind_user
           self.bind_password = bind_password
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups from LDAP."""
           username = token.claims.get("username")
           if not username:
               return []
           
           # Note: This is a simplified example
           # In production, use asyncio-compatible LDAP libraries
           server = ldap3.Server(self.server_url)
           conn = ldap3.Connection(server, self.bind_user, self.bind_password)
           
           if conn.bind():
               # Search for user groups
               search_filter = f"(&(objectClass=group)(member=cn={username},{self.base_dn}))"
               conn.search(self.base_dn, search_filter, attributes=['cn'])
               
               groups = [entry.cn.value for entry in conn.entries]
               conn.unbind()
               return groups
           
           return []

**API-based Groups Provider:**

.. code-block:: python

   import httpx
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class ApiGroupsProvider(GroupsProvider):
       """Groups provider using external API."""
       
       def __init__(self, api_base_url: str, api_key: str):
           self.api_base_url = api_base_url
           self.api_key = api_key
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups from external API."""
           username = token.claims.get("username")
           if not username:
               return []
           
           async with httpx.AsyncClient() as client:
               try:
                   response = await client.get(
                       f"{self.api_base_url}/users/{username}/groups",
                       headers={"Authorization": f"Bearer {self.api_key}"}
                   )
                   response.raise_for_status()
                   
                   data = response.json()
                   return data.get("groups", [])
               
               except httpx.HTTPError:
                   # Log error and return empty groups
                   return []

Configuration Examples
======================

**Multiple Groups Sources:**

.. code-block:: python

   class HybridGroupsProvider(GroupsProvider):
       """Combines multiple groups sources."""
       
       def __init__(self, cognito_provider, sql_provider):
           self.cognito_provider = cognito_provider
           self.sql_provider = sql_provider
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups from multiple sources."""
           # Get groups from Cognito token
           cognito_groups = await self.cognito_provider.fetch_groups(token)
           
           # Get additional groups from database
           db_groups = await self.sql_provider.fetch_groups(token)
           
           # Combine and deduplicate
           all_groups = list(set(cognito_groups + db_groups))
           
           return all_groups

**Cached Groups Provider:**

.. code-block:: python

   import asyncio
   from functools import wraps
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class CachedGroupsProvider(GroupsProvider):
       """Groups provider with caching support."""
       
       def __init__(self, base_provider: GroupsProvider, cache_ttl: int = 300):
           self.base_provider = base_provider
           self.cache_ttl = cache_ttl
           self._cache = {}
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups with caching."""
           username = token.claims.get("username")
           cache_key = f"groups:{username}"
           
           # Check cache
           if cache_key in self._cache:
               cached_data, timestamp = self._cache[cache_key]
               if asyncio.get_event_loop().time() - timestamp < self.cache_ttl:
                   return cached_data
           
           # Fetch from base provider
           groups = await self.base_provider.fetch_groups(token)
           
           # Cache result
           self._cache[cache_key] = (groups, asyncio.get_event_loop().time())
           
           return groups

Testing Groups Providers
========================

**Unit Testing:**

.. code-block:: python

   import pytest
   from unittest.mock import AsyncMock
   from auth_middleware.types.jwt import JWTAuthorizationCredentials
   from your_app.providers import CustomGroupsProvider

   @pytest.mark.asyncio
   async def test_custom_groups_provider():
       # Setup
       mock_api_client = AsyncMock()
       mock_api_client.get_user_groups.return_value = ["admin", "user"]
       
       provider = CustomGroupsProvider(mock_api_client)
       
       # Create test token
       token = JWTAuthorizationCredentials(
           jwt_token="test_token",
           header={"alg": "HS256"},
           signature="signature",
           message="message",
           claims={"username": "testuser"}
       )
       
       # Test
       groups = await provider.fetch_groups(token)
       
       # Assertions
       assert groups == ["admin", "user"]
       mock_api_client.get_user_groups.assert_called_once_with("testuser")

**Integration Testing:**

.. code-block:: python

   from fastapi.testclient import TestClient
   from your_app.main import app

   def test_groups_authorization():
       client = TestClient(app)
       
       # Test with admin token
       admin_token = "valid_admin_jwt_token"
       response = client.get(
           "/admin-only",
           headers={"Authorization": f"Bearer {admin_token}"}
       )
       assert response.status_code == 200
       
       # Test with user token
       user_token = "valid_user_jwt_token"
       response = client.get(
           "/admin-only", 
           headers={"Authorization": f"Bearer {user_token}"}
       )
       assert response.status_code == 403

Best Practices
==============

**Performance Considerations:**

1. **Caching**: Implement caching for frequently accessed groups
2. **Connection Pooling**: Use connection pools for database providers
3. **Async Operations**: Always use async/await for I/O operations
4. **Error Handling**: Gracefully handle provider failures

**Security Best Practices:**

1. **Input Validation**: Validate usernames and group names
2. **SQL Injection Prevention**: Use parameterized queries
3. **Rate Limiting**: Implement rate limiting for external API calls
4. **Logging**: Log security-relevant events without exposing sensitive data

**Error Handling:**

.. code-block:: python

   class RobustGroupsProvider(GroupsProvider):
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           try:
               return await self._fetch_groups_internal(token)
           except Exception as e:
               # Log error but don't expose to client
               logger.error(f"Failed to fetch groups: {e}")
               # Return empty groups or default groups
               return ["user"]  # Default fallback group

Migration and Deployment
=======================

**Database Migrations:**

When using SqlGroupsProvider, ensure your database schema is properly migrated:

.. code-block:: python

   # Alembic migration example
   from alembic import op
   import sqlalchemy as sa

   def upgrade():
       op.create_table('authz_groups',
           sa.Column('id', sa.String(27), primary_key=True),
           sa.Column('username', sa.String(500), nullable=False),
           sa.Column('group', sa.String(100), nullable=False)
       )
       op.create_index('idx_authz_groups_username', 'authz_groups', ['username'])

**Environment Configuration:**

.. code-block:: python

   import os
   from auth_middleware.providers.authz.sql_groups_provider import SqlGroupsProvider
   from auth_middleware.providers.authz.cognito_groups_provider import CognitoGroupsProvider

   def create_groups_provider():
       """Factory function for groups provider based on environment."""
       provider_type = os.getenv("GROUPS_PROVIDER", "cognito")
       
       if provider_type == "sql":
           return SqlGroupsProvider()
       elif provider_type == "cognito":
           return CognitoGroupsProvider()
       else:
           raise ValueError(f"Unknown groups provider: {provider_type}")

Troubleshooting
===============

**Common Issues:**

1. **Groups Not Loading**
   
   - Check token claims format
   - Verify database connectivity
   - Ensure proper provider configuration

2. **Performance Issues**
   
   - Implement caching
   - Check database query performance
   - Monitor external API response times

3. **Authorization Failures**
   
   - Verify group names match exactly
   - Check case sensitivity
   - Ensure groups are properly assigned

**Debugging:**

Enable debug logging to troubleshoot issues:

.. code-block:: python

   import logging
   logging.getLogger("auth_middleware").setLevel(logging.DEBUG)

API Reference
=============

.. autoclass:: auth_middleware.providers.authz.groups_provider.GroupsProvider
   :members:

.. autoclass:: auth_middleware.providers.authz.cognito_groups_provider.CognitoGroupsProvider
   :members:

.. autoclass:: auth_middleware.providers.authz.sql_groups_provider.SqlGroupsProvider
   :members:

See Also
========

- :doc:`permissions-provider` - For granular permission-based authorization
- :doc:`../functions` - For using groups in endpoint dependencies
- :doc:`../middleware-configuration` - For middleware setup with groups providers
