.. _authz-overview:

Scoped Permissions: Overview
============================

``auth_middleware.authz`` answers *"may this principal do X in this scope?"*. It is
additive: ``require_groups``, ``require_roles``, ``require_permissions`` and the legacy
providers keep working untouched (they are "flat RBAC").

Flat RBAC or scoped permissions?
--------------------------------

* Use ``require_groups`` / ``require_roles`` when a token claim alone decides (an
  ``admins`` group may call ``/admin``).
* Use scoped permissions when the answer depends on *where*: the same person is an editor
  of one tenant, a reader of another and a stranger to the rest, and that membership lives in
  your database or in DynamoDB, not in the token.

Concepts
--------

Principal
   The token ``sub`` plus optional token ``groups``.
Scope
   ``ScopeRef(kind, id)``, e.g. ``("studio", "<uuid>")``; ``ScopeRef.GLOBAL`` is platform-wide.
Assignment
   ``(principal, scope, role, status, revision)``. One active assignment per principal and scope.
   ``revision`` starts at 0 and grows by exactly 1 on every write (optimistic concurrency).
Role and catalog
   A role is a name. The :doc:`catalog <authz-catalog>` maps ``role -> permissions``. The model is
   additive: nothing denies.
Decision
   ``allowed``, ``not_visible`` or ``denied``.

Two failure modes, on purpose
-----------------------------

* **not visible** (HTTP 404 by default): the principal has no active assignment in the scope, *or*
  the scope does not exist. Callers cannot tell the two apart, so tenants are not enumerable.
* **denied** (HTTP 403 naming the permission): the principal has an assignment but lacks the
  permission.

A scope kind declared with ``hide_existence=False`` answers *denied* instead (used for the platform
scope, where there is nothing to hide).

Request flow
------------

.. code-block:: text

   Request -> JwtAuthMiddleware -> request.state.current_user
                 |
                 +-> Depends(require_permission("design.write", scope=ScopeFromPath(...)))
                       |-> Authz (app.state.authz)
                       |     |-> PermissionCatalog   role -> permissions
                       |     |-> store_factory(request) -> AssignmentStore (memory | SQL | DynamoDB | yours)
                       |     |-> role resolvers      [stored assignment, token groups -> role]
                       |     `-> ErrorPolicy         404 / 403 / 401
                       `-> AuthzContext returned to the handler

The guard never skips when ``AUTH_MIDDLEWARE_DISABLED`` is set, and ``Authz.install`` refuses to
start in that state unless ``allow_disabled_for_development=True``.

Next: :doc:`authz-catalog`, :doc:`authz-stores`, :doc:`authz-fastapi`, :doc:`authz-operations`,
:doc:`authz-migration`.
