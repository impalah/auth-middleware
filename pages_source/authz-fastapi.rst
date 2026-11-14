.. _authz-fastapi:

FastAPI Integration
===================

Wiring
------

.. literalinclude:: ../examples/authz_example.py
   :language: python
   :start-at: app = FastAPI(
   :end-before: @app.get(

``Authz.build`` validates the combination of sources (exactly one of ``store`` / ``store_factory``, or
only ``group_roles`` for a pure group setup). ``install`` stores the instance in ``app.state.authz``,
validates every guarded route against the catalog at startup (an unknown permission or a scope-kind mismatch
fails the application start, not a request) and closes owned resources on shutdown.

Guarding routes
---------------

.. literalinclude:: ../examples/authz_example.py
   :language: python
   :start-at: @app.get(
   :end-before: @app.put(

``require_permission(permission, scope=..., authz=...)`` returns an ``AuthzContext``
(``principal``, ``scope``, ``roles``, ``permissions``, ``attributes``) and also stores it in
``request.state.authz_context``. Scope sources: ``GlobalScope()``, ``ScopeFromPath(kind, param)``,
``ScopeFromCallable(kind, fn)``. For non-raising checks inside a handler use
``await has_permission(request, permission, scope)``.

No authenticated user, or the placeholder ``synthetic`` user the middleware creates when authentication is
disabled, gets ``401`` with ``WWW-Authenticate: Bearer``.

Error policy
------------

``ErrorPolicy`` decides which exception each outcome raises. Defaults: not visible ``404``; denied
``403`` with ``{"detail": {"error": "forbidden", "required_permission": "..."}}``; unauthenticated
``401``. Pass your own callables to ``Authz.build(error_policy=ErrorPolicy(denied=...))`` to change
status codes or bodies.

OpenAPI and architecture tests
------------------------------

``openapi_extra=permission_extra("design.write")`` publishes ``x-permission``;
``declared_permissions(app)`` returns ``{(METHOD, path): permission | None}`` for every operation, so an
architecture test can assert that no route is unguarded.

Mounted sub-applications
------------------------

A mounted app has its own ``app.state``. Either call ``install`` on each app that uses the guard, or pass
``authz=`` explicitly to ``require_permission``.
