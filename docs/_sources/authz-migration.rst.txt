.. _authz-migration:

Migrating from Flat Permissions
===============================

``require_permissions`` reads a flat list from ``request.state.current_user``; ``SqlPermissionsProvider`` reads a
global table ``authz_permissions(username, permission)``. Neither knows *which tenant* a request is
about. Nothing here changes or is removed; migrate route by route.

1. Model your tenants as a scope kind and your old permissions as catalog entries
   (:doc:`authz-catalog`). Group permissions into roles.
2. Load the old rows into assignments (one per principal and scope), for example with
   ``AssignmentService.assign`` or ``authcli authz assign``.
3. Replace ``Depends(require_permissions(["x"]))`` with
   ``Depends(require_permission("x", scope=ScopeFromPath("tenant", "tenant_id")))`` and read the
   ``AuthzContext`` it returns.
4. Platform-wide staff: map token groups to a role with ``group_roles={"staff": "PLATFORM_ADMIN"}``.
5. Keep ``AUTH_MIDDLEWARE_DISABLED`` out of environments that use the new guard: ``install`` refuses it.

The legacy ``authz_permissions`` table is independent of ``authz_assignment``; both can coexist.
