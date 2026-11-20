.. _authz-catalog:

The Permission Catalog
======================

A catalog is code or config versioned with your application; the library never reads it from a
database. It is validated when built and immutable afterwards.

In code
-------

.. literalinclude:: ../examples/authz_example.py
   :language: python
   :start-at: catalog = PermissionCatalog.from_mapping(
   :end-before: store = InMemoryAssignmentStore()

``StrEnum`` members are accepted anywhere a name is expected. ``from_mapping`` raises one
``CatalogError`` listing *all* problems: duplicate permissions, an undeclared scope kind, a role granting
an undeclared permission, empty or malformed names.

From TOML or JSON
-----------------

``PermissionCatalog.from_file(path)`` reads the same shape (``.toml`` through the standard library
``tomllib``, or ``.json``):

.. code-block:: toml

   [[scopes]]
   name = "studio"
   hide_existence = true

   [[permissions]]
   name = "design.write"
   scope = "studio"
   sensitive = false

   [roles]
   TIT = ["design.write"]

Scope kinds and ``hide_existence``
----------------------------------

Every permission belongs to exactly one scope kind, and a guard checks a permission only against a
scope of that kind (``ScopeKindMismatchError`` otherwise; ``Authz.validate_routes`` finds it at startup).
``hide_existence=True`` turns "no assignment" into *not visible* (404); ``False`` into *denied* (403).

``sensitive=True`` is metadata for audit and UIs (sensitive permissions are logged at INFO even when
allowed); it does not change enforcement.

Useful lookups: ``permissions_for(role)``, ``roles_granting(permission)``, ``spec(permission)``,
``to_mapping()`` (round-trips with ``from_mapping``).

Attributes for ABAC policies
----------------------------

An optional ``attributes`` section declares what :ref:`policies <abac>` may read besides the built-ins
(``subject.id``, ``subject.roles``, ``env.now``, ``env.hour_utc``...). Catalogs without it load unchanged.

.. code-block:: toml

   [attributes."subject.assignment.tenant_status"]
   type = "string"                      # string | int | float | bool | datetime | string_set
   enum = ["active", "suspended"]       # optional closed set of literal values

   [attributes."subject.attrs.clearance"]
   type = "int"

Only members of ``subject.claims.``, ``subject.assignment.``, ``subject.attrs.``, ``resource.attrs.`` and
``env.header.`` can be declared. In code, pass ``attributes=[AttributeSpec(...)]`` to
``PermissionCatalog.from_mapping``.
