.. _authz-api:

Scoped Permissions API Reference
================================

.. automodule:: auth_middleware.authz
   :no-members:

Runtime and guards
------------------

.. autoclass:: auth_middleware.authz.runtime.Authz
   :members: build, install, of, authorizer_for, validate_routes, aclose

.. autofunction:: auth_middleware.authz.guards.require_permission

.. autofunction:: auth_middleware.authz.guards.has_permission

Catalog and engine
------------------

.. autoclass:: auth_middleware.authz.catalog.PermissionCatalog
   :members:

.. autoclass:: auth_middleware.authz.engine.Authorizer
   :members:

Service, cache and events
-------------------------

.. autoclass:: auth_middleware.authz.service.AssignmentService
   :members:

.. autoclass:: auth_middleware.authz.cache.CachingAssignmentStore
   :members: invalidate

.. autofunction:: auth_middleware.authz.events.audit_hook

.. autofunction:: auth_middleware.authz.events.metrics_hook

Stores
------

.. autoclass:: auth_middleware.authz.stores.memory.InMemoryAssignmentStore

.. autoclass:: auth_middleware.authz.stores.sql.SqlAssignmentStore

.. autoclass:: auth_middleware.authz.stores.dynamodb.DynamoDbAssignmentStore
   :members: table_definition, create_table_if_missing

ABAC
----

.. autoclass:: auth_middleware.authz.abac.config.AbacConfig

.. autoclass:: auth_middleware.authz.abac.types.Policy

.. autoclass:: auth_middleware.authz.abac.types.NewPolicy

.. autoclass:: auth_middleware.authz.abac.service.PolicyService
   :members: create, replace, enable, disable, get

.. autoclass:: auth_middleware.authz.abac.pdp.PolicyDecisionPoint
   :members: evaluate

.. autofunction:: auth_middleware.authz.abac.validation.validate_policy

.. autofunction:: auth_middleware.authz.abac.conditions.parse_condition

.. autofunction:: auth_middleware.authz.abac.conditions.evaluate

.. autoclass:: auth_middleware.authz.abac.cache.CachingPolicySource
   :members: invalidate, invalidate_kind, on_change

.. autoclass:: auth_middleware.authz.abac.sources.StaticPolicySource
   :members: from_file

.. autoclass:: auth_middleware.authz.abac.resources.ResourceFromPath

.. autoclass:: auth_middleware.authz.stores.sql_policy.SqlPolicyStore

.. autoclass:: auth_middleware.authz.stores.sql_policy.SqlAttributeStore

.. autoclass:: auth_middleware.authz.stores.dynamodb_policy.DynamoDbPolicyStore
   :members: table_definition, create_table_if_missing

.. autoclass:: auth_middleware.authz.stores.dynamodb_policy.DynamoDbAttributeStore
