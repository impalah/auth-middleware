.. _authz-quickstart:

Scoped Permissions: Quick Start
===============================

This guide takes you from nothing to a FastAPI route that only a *project editor* may call. It uses
the in-memory store first and then shows how to switch to PostgreSQL, MySQL or DynamoDB. A complete runnable
version of the first part is ``examples/authz_example.py`` (tested in the suite).

1. Install only what you need
-----------------------------

.. code-block:: console

   pip install auth-middleware                      # core + scoped permissions, no database driver
   pip install 'auth-middleware[postgres]'          # + SQLAlchemy, asyncpg  (SQL store)
   pip install 'auth-middleware[mysql]'             # + SQLAlchemy, aiomysql (SQL store)
   pip install 'auth-middleware[sqlalchemy]'        # both SQL drivers (historical name)
   pip install 'auth-middleware[dynamodb]'          # + PynamoDB (DynamoDB store)

The scoped-permissions code itself (catalog, guard, in-memory store) is in the core package. A store whose
extra is missing raises an ``ImportError`` that names the extra to install.

2. Describe your permissions (the catalog)
------------------------------------------

Decide what a *scope* is (a tenant, a project, a studio...), which permissions exist inside it and which
roles bundle them. The catalog is validated when built and never changes afterwards.

.. literalinclude:: ../examples/authz_stores_config.py
   :language: python
   :start-at: catalog = PermissionCatalog.from_mapping(
   :end-before: def memory_authz

The same catalog can live in a TOML or JSON file (``PermissionCatalog.from_file``), see :doc:`authz-catalog`.

3. Choose a store and build ``Authz``
-------------------------------------

The store holds *who has which role in which scope*. Pick one (all pass the same contract test suite):

.. literalinclude:: ../examples/authz_stores_config.py
   :language: python
   :pyobject: memory_authz

.. literalinclude:: ../examples/authz_stores_config.py
   :language: python
   :pyobject: sql_authz

.. literalinclude:: ../examples/authz_stores_config.py
   :language: python
   :pyobject: dynamodb_authz

The SQL table comes from the Alembic revision ``a3f1c9d2b7e4`` (or from
``auth_middleware.authz.stores.sql_models.metadata`` in your own migrations). The DynamoDB table comes from
``DynamoDbAssignmentStore.table_definition(name)`` (see :doc:`infrastructure/dynamodb-setup`). Nothing in the
library reads environment variables to choose a backend: you inject it here.

To share the request's own database session (one transaction per request, row-level security) use a
per-request store instead:

.. literalinclude:: ../examples/authz_stores_config.py
   :language: python
   :pyobject: sql_per_request_authz

4. Install it on the application and guard routes
-------------------------------------------------

.. literalinclude:: ../examples/authz_example.py
   :language: python
   :start-at: app = FastAPI(
   :end-before: @app.get(

``install`` also checks at startup that every guarded route uses a permission that exists in the catalog.
Then protect a route; the scope comes from a path parameter:

.. literalinclude:: ../examples/authz_example.py
   :language: python
   :start-at: @app.put(
   :end-before: @app.get("/platform

Authentication still comes from ``JwtAuthMiddleware`` (see :doc:`user-guide`): the guard reads
``request.state.current_user`` and uses its ``id`` (the token ``sub``) as the principal.

What callers get:

* ``401``: no authenticated user.
* ``404``: the user has no active assignment in that scope, **or** the scope does not exist (the two are
  indistinguishable on purpose).
* ``403`` with ``{"detail": {"error": "forbidden", "required_permission": "..."}}``: the user belongs to the
  scope but lacks the permission.

5. Give people roles
--------------------

Your application decides who may be assigned what (invitations, "last owner" rules...). Use
``AssignmentService`` from your own endpoints, or the CLI for operations:

.. code-block:: python

   from auth_middleware.authz import AssignmentService, ScopeRef

   service = AssignmentService(store, catalog)   # store: any store with the write side
   scope = ScopeRef("project", "p-1")
   assignment = await service.assign("user-sub", scope, "EDITOR")
   await service.change_role("user-sub", scope, "VIEWER", expected_revision=assignment.revision)
   await service.revoke("user-sub", scope, expected_revision=assignment.revision + 1)

.. code-block:: console

   export AUTHZ_SQLALCHEMY_DATABASE_URI=postgresql+asyncpg://user:pw@host/db   # or AUTHZ_DYNAMODB_TABLE
   authcli authz assign --store sqlalchemy --principal user-sub --scope project:p-1 --role EDITOR
   authcli authz list   --store sqlalchemy --scope project:p-1

Revisions make concurrent edits safe: a stale ``expected_revision`` raises ``RevisionConflictError``.
Platform-wide staff can be derived from token groups instead of stored assignments:
``Authz.build(..., group_roles={"staff": "PLATFORM_ADMIN"})``.

6. Test your routes
-------------------

Use the in-memory store and drive the app with ``httpx`` exactly as ``tests/authz/test_example.py`` does. Add an
architecture test that no route is left unguarded with ``declared_permissions(app)`` (see :doc:`authz-fastapi`).

Where next
----------

* Concepts and the 404/403 rule: :doc:`authz-overview`
* Stores, contract tests, own adapters: :doc:`authz-stores`
* Error policy, OpenAPI, mounted apps: :doc:`authz-fastapi`
* Operations (cache, audit, metrics): :doc:`authz-operations`
