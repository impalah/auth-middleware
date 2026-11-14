.. _authz-operations:

Operations: Service, CLI, Cache, Audit
======================================

Assignment service
------------------

``AssignmentService(admin, catalog, before_change=[...], after_change=[...])`` validates roles against
the catalog (``UnknownRoleError``; a role may only be assigned in a scope of the kind its permissions
belong to) and runs your hooks. ``before_change`` may raise to veto: nothing is written. That is where
application rules live, for example "the last owner cannot leave" (see the docstring of
``AssignmentService`` for the full hook). ``after_change`` receives the written assignment; every after hook runs even if an earlier one raises (the first
error is re-raised afterwards).

.. warning::

   Changes of one scope are serialised **within a process** (hooks and write run under a per-scope lock), so
   concurrent requests cannot both pass the same check. Several processes still race (two owners revoking each other
   on different servers may leave a scope with no owner): enforce hard invariants in your store (a constraint or a
   transaction in your own adapter) as well.

CLI
---

.. code-block:: console

   $ export AUTHZ_SQLALCHEMY_DATABASE_URI=postgresql+asyncpg://...   # or AUTHZ_DYNAMODB_TABLE
   $ authcli authz assign --store sqlalchemy --principal SUB --scope studio:UUID --role EDI
   $ authcli authz list   --store sqlalchemy --scope studio:UUID
   $ authcli authz revoke --store sqlalchemy --principal SUB --scope studio:UUID --expected-revision 0

``--catalog FILE`` validates roles. The CLI is the only place that reads these variables.

Cache (opt-in)
--------------

``CachingAssignmentStore(store, ttl_seconds=...)`` caches ``get_assignment`` in-process (negative results for
a quarter of the TTL). It is **never enabled by default**. Writes through the same instance invalidate at
once; writes from *other processes* become visible only after the TTL, so a revoked principal can keep
access that long. TTLs above 60 s need ``i_understand_stale_authorization=True``.

Audit and metrics
-----------------

``AuthzHooks(on_decision=...)`` receives one ``DecisionEvent`` per decision (ids and permission names only; never
e-mails or tokens). ``audit_hook(AuditLogger())`` logs it (denied WARNING, not visible INFO, allowed DEBUG,
sensitive permissions INFO); ``metrics_hook(MetricsCollector())`` counts per outcome and permission
(``get_authz_metrics()``); ``combine_hooks`` chains several. A hook that raises is logged and ignored:
auditing never turns an allowed request into a 500.
