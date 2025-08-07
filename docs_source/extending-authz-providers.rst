.. _extending-authz-providers:

Extending Authorization Providers
=================================

This guide explains how to extend the auth-middleware authorization system by creating custom Groups and Permissions providers. You'll learn how to integrate with external systems, implement custom business logic, and create robust authorization solutions.

Overview
========

The auth-middleware authorization system is built around two core interfaces:

- **GroupsProvider**: Fetches user groups/roles for role-based access control (RBAC)
- **PermissionsProvider**: Fetches user permissions for fine-grained access control

Both interfaces are designed to be simple yet flexible, allowing integration with various backend systems and custom business logic.

Understanding the Provider Interface
====================================

**GroupsProvider Interface:**

.. code-block:: python

   from abc import ABCMeta, abstractmethod
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class GroupsProvider(metaclass=ABCMeta):
       @abstractmethod
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups for the user identified by the token."""
           pass

**PermissionsProvider Interface:**

.. code-block:: python

   from abc import ABCMeta, abstractmethod
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class PermissionsProvider(metaclass=ABCMeta):
       @abstractmethod
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions for the user identified by the token."""
           pass

**Token Information Available:**

.. code-block:: python

   # JWTAuthorizationCredentials provides:
   token.jwt_token      # Raw JWT token string
   token.header         # JWT header dict
   token.signature      # JWT signature
   token.message        # JWT payload
   token.claims         # Decoded JWT claims dict

   # Common claims available:
   username = token.claims.get("username")
   user_id = token.claims.get("sub")
   email = token.claims.get("email")
   custom_claim = token.claims.get("custom_field")

Integration Patterns
====================

External Database Integration
-----------------------------

**MongoDB Groups Provider:**

.. code-block:: python

   from motor.motor_asyncio import AsyncIOMotorClient
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class MongoGroupsProvider(GroupsProvider):
       """Groups provider using MongoDB."""
       
       def __init__(self, connection_string: str, database_name: str):
           self.client = AsyncIOMotorClient(connection_string)
           self.db = self.client[database_name]
           self.collection = self.db.user_groups
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups from MongoDB."""
           username = token.claims.get("username")
           if not username:
               return []
           
           # Find user document
           user_doc = await self.collection.find_one({"username": username})
           
           if user_doc:
               return user_doc.get("groups", [])
           
           return []
       
       async def close(self):
           """Clean up MongoDB connection."""
           self.client.close()

**Elasticsearch Permissions Provider:**

.. code-block:: python

   from elasticsearch import AsyncElasticsearch
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class ElasticsearchPermissionsProvider(PermissionsProvider):
       """Permissions provider using Elasticsearch."""
       
       def __init__(self, hosts: list, index_name: str = "user_permissions"):
           self.es = AsyncElasticsearch(hosts=hosts)
           self.index_name = index_name
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions from Elasticsearch."""
           username = token.claims.get("username")
           if not username:
               return []
           
           try:
               # Search for user permissions
               query = {
                   "query": {
                       "term": {"username.keyword": username}
                   }
               }
               
               response = await self.es.search(
                   index=self.index_name,
                   body=query
               )
               
               permissions = []
               for hit in response["hits"]["hits"]:
                   permissions.extend(hit["_source"].get("permissions", []))
               
               return list(set(permissions))  # Deduplicate
           
           except Exception as e:
               logger.error(f"Elasticsearch error: {e}")
               return []
       
       async def close(self):
           """Clean up Elasticsearch connection."""
           await self.es.close()

Microservices Integration
------------------------

**gRPC Groups Provider:**

.. code-block:: python

   import grpc
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials
   # Import your generated gRPC stubs
   from your_proto import user_service_pb2, user_service_pb2_grpc

   class GrpcGroupsProvider(GroupsProvider):
       """Groups provider using gRPC service."""
       
       def __init__(self, grpc_endpoint: str):
           self.grpc_endpoint = grpc_endpoint
           self._channel = None
           self._stub = None
       
       async def _get_stub(self):
           if self._stub is None:
               self._channel = grpc.aio.insecure_channel(self.grpc_endpoint)
               self._stub = user_service_pb2_grpc.UserServiceStub(self._channel)
           return self._stub
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups via gRPC."""
           username = token.claims.get("username")
           if not username:
               return []
           
           try:
               stub = await self._get_stub()
               request = user_service_pb2.GetUserGroupsRequest(username=username)
               response = await stub.GetUserGroups(request)
               
               return list(response.groups)
           
           except grpc.RpcError as e:
               logger.error(f"gRPC error: {e}")
               return []
       
       async def close(self):
           """Clean up gRPC connection."""
           if self._channel:
               await self._channel.close()

**GraphQL Permissions Provider:**

.. code-block:: python

   import httpx
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class GraphQLPermissionsProvider(PermissionsProvider):
       """Permissions provider using GraphQL API."""
       
       def __init__(self, graphql_endpoint: str, api_key: str):
           self.graphql_endpoint = graphql_endpoint
           self.api_key = api_key
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions via GraphQL."""
           username = token.claims.get("username")
           if not username:
               return []
           
           query = """
           query GetUserPermissions($username: String!) {
               user(username: $username) {
                   permissions {
                       name
                   }
                   roles {
                       permissions {
                           name
                       }
                   }
               }
           }
           """
           
           async with httpx.AsyncClient() as client:
               try:
                   response = await client.post(
                       self.graphql_endpoint,
                       json={
                           "query": query,
                           "variables": {"username": username}
                       },
                       headers={"Authorization": f"Bearer {self.api_key}"}
                   )
                   
                   response.raise_for_status()
                   data = response.json()
                   
                   if "errors" in data:
                       logger.error(f"GraphQL errors: {data['errors']}")
                       return []
                   
                   user_data = data["data"]["user"]
                   if not user_data:
                       return []
                   
                   # Collect permissions from user and roles
                   permissions = set()
                   
                   # Direct permissions
                   for perm in user_data.get("permissions", []):
                       permissions.add(perm["name"])
                   
                   # Role-based permissions
                   for role in user_data.get("roles", []):
                       for perm in role.get("permissions", []):
                           permissions.add(perm["name"])
                   
                   return list(permissions)
               
               except httpx.HTTPError as e:
                   logger.error(f"GraphQL HTTP error: {e}")
                   return []

Cloud Services Integration
--------------------------

**AWS DynamoDB Groups Provider:**

.. code-block:: python

   import boto3
   from botocore.exceptions import ClientError
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class DynamoDBGroupsProvider(GroupsProvider):
       """Groups provider using AWS DynamoDB."""
       
       def __init__(self, table_name: str, region_name: str = "us-east-1"):
           self.table_name = table_name
           self.dynamodb = boto3.resource("dynamodb", region_name=region_name)
           self.table = self.dynamodb.Table(table_name)
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups from DynamoDB."""
           username = token.claims.get("username")
           if not username:
               return []
           
           try:
               response = self.table.get_item(Key={"username": username})
               
               if "Item" in response:
                   return response["Item"].get("groups", [])
               
               return []
           
           except ClientError as e:
               logger.error(f"DynamoDB error: {e}")
               return []

**Azure Cosmos DB Permissions Provider:**

.. code-block:: python

   from azure.cosmos.aio import CosmosClient
   from azure.cosmos import exceptions
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class CosmosDBPermissionsProvider(PermissionsProvider):
       """Permissions provider using Azure Cosmos DB."""
       
       def __init__(self, endpoint: str, key: str, database_name: str, container_name: str):
           self.client = CosmosClient(endpoint, key)
           self.database = self.client.get_database_client(database_name)
           self.container = self.database.get_container_client(container_name)
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions from Cosmos DB."""
           username = token.claims.get("username")
           if not username:
               return []
           
           try:
               # Query for user permissions
               query = "SELECT * FROM c WHERE c.username = @username"
               parameters = [{"name": "@username", "value": username}]
               
               items = self.container.query_items(
                   query=query,
                   parameters=parameters,
                   enable_cross_partition_query=True
               )
               
               permissions = []
               async for item in items:
                   permissions.extend(item.get("permissions", []))
               
               return list(set(permissions))
           
           except exceptions.CosmosHttpResponseError as e:
               logger.error(f"Cosmos DB error: {e}")
               return []
       
       async def close(self):
           """Clean up Cosmos DB connection."""
           await self.client.close()

Advanced Patterns
=================

Multi-Source Provider
--------------------

Combine multiple authorization sources:

.. code-block:: python

   class MultiSourceGroupsProvider(GroupsProvider):
       """Groups provider that combines multiple sources."""
       
       def __init__(self, providers: list[GroupsProvider], merge_strategy: str = "union"):
           self.providers = providers
           self.merge_strategy = merge_strategy
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups from multiple sources."""
           all_groups = []
           
           # Fetch from all providers
           for provider in self.providers:
               try:
                   provider_groups = await provider.fetch_groups(token)
                   all_groups.append(set(provider_groups))
               except Exception as e:
                   logger.error(f"Provider error: {e}")
                   # Continue with other providers
           
           if not all_groups:
               return []
           
           # Apply merge strategy
           if self.merge_strategy == "union":
               # Union of all groups
               result = set()
               for groups in all_groups:
                   result.update(groups)
               return list(result)
           
           elif self.merge_strategy == "intersection":
               # Intersection of all groups
               result = all_groups[0]
               for groups in all_groups[1:]:
                   result.intersection_update(groups)
               return list(result)
           
           else:
               raise ValueError(f"Unknown merge strategy: {self.merge_strategy}")

Hierarchical Permissions Provider
---------------------------------

Implement permission inheritance and hierarchies:

.. code-block:: python

   class HierarchicalPermissionsProvider(PermissionsProvider):
       """Permissions provider with hierarchy support."""
       
       def __init__(self, base_provider: PermissionsProvider):
           self.base_provider = base_provider
           self.hierarchy = {
               "admin": {
                   "inherits": [],
                   "permissions": ["*"]  # Wildcard for all permissions
               },
               "manager": {
                   "inherits": ["user"],
                   "permissions": ["manage:*"]
               },
               "user": {
                   "inherits": [],
                   "permissions": ["read:*"]
               }
           }
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions with hierarchy resolution."""
           # Get base permissions and groups
           base_permissions = await self.base_provider.fetch_permissions(token)
           user_groups = token.claims.get("groups", [])
           
           # Resolve hierarchical permissions
           all_permissions = set(base_permissions)
           
           for group in user_groups:
               group_permissions = await self._resolve_group_permissions(group)
               all_permissions.update(group_permissions)
           
           return list(all_permissions)
       
       async def _resolve_group_permissions(self, group: str, visited: set = None) -> set[str]:
           """Recursively resolve group permissions."""
           if visited is None:
               visited = set()
           
           if group in visited or group not in self.hierarchy:
               return set()
           
           visited.add(group)
           permissions = set()
           
           # Get direct permissions
           group_config = self.hierarchy[group]
           permissions.update(group_config.get("permissions", []))
           
           # Get inherited permissions
           for inherited_group in group_config.get("inherits", []):
               inherited_permissions = await self._resolve_group_permissions(inherited_group, visited)
               permissions.update(inherited_permissions)
           
           return permissions

Context-Aware Provider
---------------------

Make authorization decisions based on request context:

.. code-block:: python

   from contextvars import ContextVar
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   # Context variables to store request information
   request_context: ContextVar[dict] = ContextVar("request_context", default={})

   class ContextAwarePermissionsProvider(PermissionsProvider):
       """Permissions provider that considers request context."""
       
       def __init__(self, base_provider: PermissionsProvider):
           self.base_provider = base_provider
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions considering request context."""
           # Get base permissions
           base_permissions = await self.base_provider.fetch_permissions(token)
           
           # Get request context
           context = request_context.get({})
           
           # Apply context-based modifications
           permissions = set(base_permissions)
           
           # Time-based permissions
           if self._is_business_hours():
               permissions.add("business_hours:access")
           
           # IP-based permissions
           client_ip = context.get("client_ip")
           if self._is_internal_ip(client_ip):
               permissions.add("internal:access")
           
           # Resource-based permissions
           resource_id = context.get("resource_id")
           if resource_id and await self._user_owns_resource(token, resource_id):
               permissions.add(f"owner:{resource_id}")
           
           return list(permissions)
       
       def _is_business_hours(self) -> bool:
           """Check if current time is during business hours."""
           from datetime import datetime
           now = datetime.now()
           return 9 <= now.hour <= 17 and now.weekday() < 5
       
       def _is_internal_ip(self, ip: str) -> bool:
           """Check if IP is from internal network."""
           import ipaddress
           if not ip:
               return False
           try:
               ip_obj = ipaddress.ip_address(ip)
               return ip_obj.is_private
           except ValueError:
               return False
       
       async def _user_owns_resource(self, token: JWTAuthorizationCredentials, resource_id: str) -> bool:
           """Check if user owns the specified resource."""
           # Implement your ownership logic here
           username = token.claims.get("username")
           # Query your database to check ownership
           return await self._check_ownership(username, resource_id)

Caching and Performance
======================

Advanced Caching Provider
-------------------------

.. code-block:: python

   import asyncio
   import hashlib
   import json
   from datetime import datetime, timedelta
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class AdvancedCachedGroupsProvider(GroupsProvider):
       """Groups provider with advanced caching features."""
       
       def __init__(self, base_provider: GroupsProvider, 
                    cache_ttl: int = 300,
                    max_cache_size: int = 1000,
                    enable_negative_caching: bool = True):
           self.base_provider = base_provider
           self.cache_ttl = cache_ttl
           self.max_cache_size = max_cache_size
           self.enable_negative_caching = enable_negative_caching
           
           self._cache = {}
           self._access_times = {}
           self._lock = asyncio.Lock()
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups with advanced caching."""
           cache_key = self._generate_cache_key(token)
           
           # Check cache
           cached_result = await self._get_from_cache(cache_key)
           if cached_result is not None:
               return cached_result
           
           # Fetch from base provider
           async with self._lock:
               # Double-check cache after acquiring lock
               cached_result = await self._get_from_cache(cache_key)
               if cached_result is not None:
                   return cached_result
               
               try:
                   groups = await self.base_provider.fetch_groups(token)
                   await self._store_in_cache(cache_key, groups)
                   return groups
               
               except Exception as e:
                   # Store negative cache entry if enabled
                   if self.enable_negative_caching:
                       await self._store_in_cache(cache_key, [], ttl=60)  # Short TTL for errors
                   raise e
       
       def _generate_cache_key(self, token: JWTAuthorizationCredentials) -> str:
           """Generate a unique cache key for the token."""
           key_data = {
               "username": token.claims.get("username"),
               "sub": token.claims.get("sub"),
               "iat": token.claims.get("iat"),  # Include token issue time
           }
           key_string = json.dumps(key_data, sort_keys=True)
           return hashlib.sha256(key_string.encode()).hexdigest()
       
       async def _get_from_cache(self, cache_key: str):
           """Get value from cache if valid."""
           if cache_key in self._cache:
               cached_data, expiry_time = self._cache[cache_key]
               
               if datetime.now() < expiry_time:
                   # Update access time for LRU
                   self._access_times[cache_key] = datetime.now()
                   return cached_data
               else:
                   # Expired, remove from cache
                   del self._cache[cache_key]
                   del self._access_times[cache_key]
           
           return None
       
       async def _store_in_cache(self, cache_key: str, data: list[str], ttl: int = None):
           """Store data in cache with TTL."""
           if ttl is None:
               ttl = self.cache_ttl
           
           expiry_time = datetime.now() + timedelta(seconds=ttl)
           
           # Implement LRU eviction if cache is full
           if len(self._cache) >= self.max_cache_size:
               await self._evict_lru()
           
           self._cache[cache_key] = (data, expiry_time)
           self._access_times[cache_key] = datetime.now()
       
       async def _evict_lru(self):
           """Evict least recently used item."""
           if self._access_times:
               lru_key = min(self._access_times, key=self._access_times.get)
               del self._cache[lru_key]
               del self._access_times[lru_key]
       
       def clear_cache(self, pattern: str = None):
           """Clear cache entries matching pattern."""
           if pattern is None:
               self._cache.clear()
               self._access_times.clear()
           else:
               # Clear entries matching pattern
               keys_to_remove = [k for k in self._cache.keys() if pattern in k]
               for key in keys_to_remove:
                   del self._cache[key]
                   del self._access_times[key]

Error Handling and Resilience
=============================

Circuit Breaker Provider
-----------------------

.. code-block:: python

   import asyncio
   from enum import Enum
   from datetime import datetime, timedelta
   from auth_middleware.providers.authz.permissions_provider import PermissionsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class CircuitState(Enum):
       CLOSED = "closed"
       OPEN = "open"
       HALF_OPEN = "half_open"

   class CircuitBreakerPermissionsProvider(PermissionsProvider):
       """Permissions provider with circuit breaker pattern."""
       
       def __init__(self, base_provider: PermissionsProvider,
                    failure_threshold: int = 5,
                    timeout: int = 60,
                    fallback_permissions: list[str] = None):
           self.base_provider = base_provider
           self.failure_threshold = failure_threshold
           self.timeout = timeout
           self.fallback_permissions = fallback_permissions or ["guest"]
           
           self.state = CircuitState.CLOSED
           self.failure_count = 0
           self.last_failure_time = None
           self._lock = asyncio.Lock()
       
       async def fetch_permissions(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch permissions with circuit breaker protection."""
           async with self._lock:
               if self.state == CircuitState.OPEN:
                   if self._should_attempt_reset():
                       self.state = CircuitState.HALF_OPEN
                   else:
                       logger.warning("Circuit breaker open, returning fallback permissions")
                       return self.fallback_permissions
               
               try:
                   permissions = await self.base_provider.fetch_permissions(token)
                   await self._on_success()
                   return permissions
               
               except Exception as e:
                   await self._on_failure()
                   logger.error(f"Permission provider failed: {e}")
                   return self.fallback_permissions
       
       def _should_attempt_reset(self) -> bool:
           """Check if circuit breaker should attempt reset."""
           if self.last_failure_time is None:
               return True
           
           return datetime.now() - self.last_failure_time > timedelta(seconds=self.timeout)
       
       async def _on_success(self):
           """Handle successful call."""
           self.failure_count = 0
           self.state = CircuitState.CLOSED
       
       async def _on_failure(self):
           """Handle failed call."""
           self.failure_count += 1
           self.last_failure_time = datetime.now()
           
           if self.failure_count >= self.failure_threshold:
               self.state = CircuitState.OPEN
               logger.warning(f"Circuit breaker opened after {self.failure_count} failures")

Retry Provider
-------------

.. code-block:: python

   import asyncio
   from auth_middleware.providers.authz.groups_provider import GroupsProvider
   from auth_middleware.types.jwt import JWTAuthorizationCredentials

   class RetryGroupsProvider(GroupsProvider):
       """Groups provider with retry logic."""
       
       def __init__(self, base_provider: GroupsProvider,
                    max_retries: int = 3,
                    backoff_factor: float = 1.0):
           self.base_provider = base_provider
           self.max_retries = max_retries
           self.backoff_factor = backoff_factor
       
       async def fetch_groups(self, token: JWTAuthorizationCredentials) -> list[str]:
           """Fetch groups with retry logic."""
           last_exception = None
           
           for attempt in range(self.max_retries + 1):
               try:
                   return await self.base_provider.fetch_groups(token)
               
               except Exception as e:
                   last_exception = e
                   
                   if attempt < self.max_retries:
                       # Calculate backoff delay
                       delay = self.backoff_factor * (2 ** attempt)
                       logger.warning(f"Attempt {attempt + 1} failed, retrying in {delay}s: {e}")
                       await asyncio.sleep(delay)
                   else:
                       logger.error(f"All {self.max_retries + 1} attempts failed")
           
           # Re-raise the last exception
           raise last_exception

Testing Custom Providers
========================

**Comprehensive Test Suite:**

.. code-block:: python

   import pytest
   from unittest.mock import AsyncMock, patch
   from auth_middleware.types.jwt import JWTAuthorizationCredentials
   from your_app.providers import CustomGroupsProvider

   class TestCustomGroupsProvider:
       
       @pytest.fixture
       def token(self):
           return JWTAuthorizationCredentials(
               jwt_token="test_token",
               header={"alg": "HS256"},
               signature="signature",
               message="message",
               claims={"username": "testuser", "sub": "123"}
           )
       
       @pytest.fixture
       def provider(self):
           return CustomGroupsProvider(api_endpoint="http://test.com")
       
       @pytest.mark.asyncio
       async def test_fetch_groups_success(self, provider, token):
           """Test successful group fetching."""
           with patch.object(provider, '_api_call', return_value=["admin", "user"]):
               groups = await provider.fetch_groups(token)
               assert groups == ["admin", "user"]
       
       @pytest.mark.asyncio
       async def test_fetch_groups_empty_username(self, provider):
           """Test handling of empty username."""
           token = JWTAuthorizationCredentials(
               jwt_token="test_token",
               header={"alg": "HS256"},
               signature="signature", 
               message="message",
               claims={}  # No username
           )
           
           groups = await provider.fetch_groups(token)
           assert groups == []
       
       @pytest.mark.asyncio
       async def test_fetch_groups_api_error(self, provider, token):
           """Test handling of API errors."""
           with patch.object(provider, '_api_call', side_effect=Exception("API Error")):
               groups = await provider.fetch_groups(token)
               assert groups == []  # Should return empty list on error
       
       @pytest.mark.asyncio
       async def test_fetch_groups_timeout(self, provider, token):
           """Test handling of timeout."""
           with patch.object(provider, '_api_call', side_effect=asyncio.TimeoutError):
               groups = await provider.fetch_groups(token)
               assert groups == []

Deployment Considerations
========================

**Configuration Management:**

.. code-block:: python

   import os
   from auth_middleware.providers.authz.sql_groups_provider import SqlGroupsProvider
   from auth_middleware.providers.authz.cognito_groups_provider import CognitoGroupsProvider
   from your_app.providers import CustomGroupsProvider

   def create_groups_provider():
       """Factory function for groups provider."""
       provider_type = os.getenv("GROUPS_PROVIDER_TYPE", "cognito")
       
       if provider_type == "sql":
           return SqlGroupsProvider()
       elif provider_type == "cognito":
           return CognitoGroupsProvider()
       elif provider_type == "custom":
           api_endpoint = os.getenv("CUSTOM_GROUPS_API_ENDPOINT")
           api_key = os.getenv("CUSTOM_GROUPS_API_KEY")
           return CustomGroupsProvider(api_endpoint, api_key)
       else:
           raise ValueError(f"Unknown groups provider type: {provider_type}")

**Health Checks:**

.. code-block:: python

   from fastapi import FastAPI
   from auth_middleware.providers.authz.groups_provider import GroupsProvider

   app = FastAPI()

   @app.get("/health/groups-provider")
   async def health_check_groups_provider(groups_provider: GroupsProvider = Depends(get_groups_provider)):
       """Health check endpoint for groups provider."""
       try:
           # Create a test token
           test_token = create_test_token()
           
           # Try to fetch groups (with timeout)
           groups = await asyncio.wait_for(
               groups_provider.fetch_groups(test_token),
               timeout=5.0
           )
           
           return {"status": "healthy", "provider": type(groups_provider).__name__}
       
       except Exception as e:
           return {"status": "unhealthy", "error": str(e)}, 503

Best Practices Summary
=====================

**Design Principles:**

1. **Single Responsibility**: Each provider should focus on one authorization source
2. **Fail-Safe**: Always return safe defaults on errors
3. **Async-First**: Use async/await for all I/O operations
4. **Testable**: Design for easy unit and integration testing
5. **Observable**: Include comprehensive logging and metrics

**Performance Guidelines:**

1. **Caching**: Implement appropriate caching strategies
2. **Connection Pooling**: Use connection pools for databases
3. **Timeouts**: Set reasonable timeouts for external calls
4. **Circuit Breakers**: Protect against cascading failures

**Security Considerations:**

1. **Input Validation**: Validate all inputs from tokens
2. **Error Handling**: Don't expose sensitive information in errors
3. **Logging**: Log security events without exposing secrets
4. **Principle of Least Privilege**: Return minimal necessary permissions

See Also
========

- :doc:`groups-provider` - Built-in groups providers
- :doc:`permissions-provider` - Built-in permissions providers  
- :doc:`../middleware-configuration` - Middleware setup and configuration
- :doc:`../functions` - Using authorization in endpoints
