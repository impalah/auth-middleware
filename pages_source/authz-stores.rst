.. _authz-stores:

Assignment Stores
=================

A store is anything implementing the ``AssignmentStore`` port (``get_assignment``,
``list_assignments``); the optional ``AssignmentAdmin`` port adds ``assign``, ``change_role``,
``revoke`` and ``list_for_scope``. The backend is injected at startup, never read from the
environment by the library.

* ``InMemoryAssignmentStore``: no extra; tests, examples and the reference implementation.
* ``SqlAssignmentStore``: ``pip install 'auth-middleware[postgres]'`` or ``[mysql]`` (``[sqlalchemy]`` installs both
  drivers); table ``authz_assignment``.
* ``DynamoDbAssignmentStore``: ``pip install 'auth-middleware[dynamodb]'``; PynamoDB, single table
  (see :doc:`infrastructure/dynamodb-setup`).

Contract semantics (all stores)
-------------------------------

* ``get_assignment`` returns ``None`` when the scope or the principal does not exist.
* A revoked assignment may be returned; the engine treats it as absent.
* ``assign`` on an active assignment raises ``RevisionConflictError``; on a revoked one it
  reactivates it with ``revision + 1``.
* Every write bumps ``revision`` by exactly 1; a stale ``expected_revision`` raises
  ``RevisionConflictError``.

SQLAlchemy
----------

``SqlAssignmentStore`` accepts an ``async_sessionmaker`` (short session per call), a callable
returning an async context manager, or an **already open** ``AsyncSession``. With an open session the
store never commits, rolls back or closes it: reads and writes happen in the caller's transaction.
``before_query(session, scope)`` runs before every statement; that is where an application binds
row-level security. The table comes from an Alembic revision (``a3f1c9d2b7e4``) or from
``auth_middleware.authz.stores.sql_models.metadata`` included in your own ``target_metadata``.

Per-request store (sharing the request's session)
-------------------------------------------------

``Authz.build(store_factory=...)`` calls the factory once per request, lazily, when the guard runs.
*Sketch* (the same shape is exercised by ``tests/authz/test_sql_store_unit.py`` and the PostgreSQL
RLS test in ``tests/authz/integration/``):

.. code-block:: python

   async def store_for(request):
       session = request.state.session            # opened by your own dependency
       async def bind_rls(session, scope):
           if scope is not None:
               await session.execute(
                   text("SELECT set_config('app.scope_id', :id, true)"), {"id": scope.id}
               )
       return SqlAssignmentStore(session, before_query=bind_rls)

   Authz.build(catalog=catalog, store_factory=store_for).install(app)

FastAPI resolves the sub-dependencies of a route in declaration order: a dependency that must run
before the check (e.g. one that opens the session) has to be declared before the guard.

DynamoDB
--------

``DynamoDbAssignmentStore(table_name=...)`` uses PynamoDB, which is synchronous: each call runs in a
worker thread. ``get_assignment`` uses consistent reads by default (a just-revoked principal must not be
admitted); ``list_assignments`` uses the GSI and may lag. Throttling that survives retries raises
``StoreUnavailableError``.

Tested engines
--------------

The same contract suite runs against PostgreSQL 17 and MySQL 8 (``SqlAssignmentStore``) and DynamoDB
(``DynamoDbAssignmentStore``). ``make test-floci`` starts `Floci <https://github.com/floci-io/floci>`_ with
testcontainers; it emulates DynamoDB and starts real PostgreSQL and MySQL containers through its RDS emulation
(Docker required). On MySQL the identifier columns use ``utf8mb4_bin``, because its default collations would treat
``Abc`` and ``abc`` as the same principal.

Writing your own adapter
------------------------

Implement the two read methods over your own tables and subclass the shipped suite:

.. code-block:: python

   from auth_middleware.authz.testing import AssignmentStoreContract

   class TestMyStore(AssignmentStoreContract):
       supports_attributes = False            # if your store cannot keep attributes

       @asynccontextmanager
       async def make_store(self):
           yield MyStore(...)

The suite covers twelve behaviours, including 20 concurrent ``assign`` calls with exactly one winner.
