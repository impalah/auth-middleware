.. _abac:

Attribute-Based Access Control (ABAC)
=====================================

Roles answer *"what can this member do in this scope?"*. Some rules depend on **data** instead:

* a suspended studio cannot be modified, whatever the role;
* only the owner of a design may delete it, even for an ``OWNER`` of the studio;
* support staff read only during office hours and never read billing;
* a document needs a clearance at least as high as its classification.

ABAC adds those rules **on top of** the roles, without replacing them. A *policy* is a small
JSON/TOML document that can be stored in the same databases as the assignments (SQLAlchemy, DynamoDB),
versioned, audited and validated before it is accepted.

.. contents::
   :local:
   :depth: 2

Without a policy source nothing changes: ``Authz.build(...)`` without ``abac=`` behaves exactly as in
0.7.0.

The model
---------

.. code-block:: text

   request ─> role check (unchanged: 404 not visible / 403 role lacks it)
                 │
                 └─> policies that apply (scope + permission)
                       deny    -> applies when its condition is TRUE or INDETERMINATE
                       require -> denies unless its condition is TRUE
                       permit  -> grants when TRUE (``grant`` mode only, experimental)

A **deny overrides** everything. Evaluation is *three-valued*: a missing attribute or a type mismatch is
``INDETERMINATE``, and the decision fails closed in both directions (a ``deny`` on an unknown value
denies; a ``require`` on an unknown value is not satisfied).

Modes
~~~~~

``restrict`` (default)
   Policies only **narrow** what the roles granted. A wrong policy can lock people out, never let anybody
   in.

``grant`` (**experimental**)
   A ``permit`` policy whose condition is TRUE grants the permission even if the role does not. It never
   widens visibility: a principal who is not a member of the scope still gets 404. Semantics may be
   refined in a minor release.

Anatomy of a policy
-------------------

.. literalinclude:: ../examples/abac_policies.toml
   :language: toml
   :lines: 5-10

``id``
   Human-chosen, unique across the whole store (``[a-z0-9][a-z0-9_.-]{0,99}``).
``effect``
   ``deny``, ``require`` or ``permit``.
``permissions``
   Exact catalog names or ``*`` patterns (``design.*``, ``*.write``). A pattern that matches nothing, or
   that spans scope kinds, is rejected when the policy is written.
``scope``
   ``{kind = "studio"}`` (every scope of the kind) or ``{kind = "studio", id = "s1"}``. The scope of a
   stored policy cannot change.
``hide``
   A denial answers *not visible* (404, byte-identical to a non-member's answer) instead of 403.
``enforce``
   ``false`` is **shadow mode**: the policy is evaluated and reported in the audit event
   (``shadow_policy_ids``) but never enforced. See :ref:`abac-rollout`.
``priority``
   Lower is evaluated first (it decides which denial is reported; it never changes the outcome).

The condition language
----------------------

A condition is a one-key object. There is **no** ``eval``, no regular expression, no arithmetic and no
user-defined operator: policies are data. Operands are literals or ``{attr = "namespace.name"}``.

.. list-table::
   :header-rows: 1
   :widths: 24 76

   * - Operator
     - Meaning
   * - ``all`` / ``any`` / ``not``
     - Logic over conditions.
   * - ``eq`` ``ne``
     - Equality of two values of the **same type** (a number never equals a string or a bool).
   * - ``lt`` ``lte`` ``gt`` ``gte``
     - Order over numbers or datetimes (ISO-8601 with offset against ``env.now``).
   * - ``in`` ``not_in``
     - ``[value, list]``: membership.
   * - ``contains``
     - ``[set, value]`` or ``[string, string]``.
   * - ``intersects`` ``subset``
     - ``[set, set]``.
   * - ``starts_with`` ``ends_with``
     - ``[string, string]``.
   * - ``exists``
     - ``{attr = ...}`` is present and not ``null``; the only operator that turns absence into a
       definite answer.

Limits (checked when a condition is parsed): depth 8, 64 nodes, lists of 100 items, strings of 256
characters, a policy document of 16 KB.

Attributes
----------

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Namespace
     - Comes from
   * - ``subject.id|email|groups|roles``
     - the authenticated principal and the roles found in the scope
   * - ``subject.assignment.<name>``
     - the ``attributes`` of the principal's assignment (e.g. ``tenant_status``)
   * - ``subject.claims.<name>``
     - token claims, **only** those in ``AbacConfig.claims_allowlist``
   * - ``subject.attrs.<name>``
     - persisted principal attributes (``AttributeStore``)
   * - ``resource.kind|id``
     - the guard's ``resource=``
   * - ``resource.attrs.<name>``
     - the route's **loader** (your own data) or, without a loader, persisted resource attributes
   * - ``action.permission``
     - the permission being checked
   * - ``env.now|hour_utc|weekday|method|path|ip``
     - the request (``env.ip`` honours ``X-Forwarded-For`` only from ``trusted_proxies``)
   * - ``env.header.<name>``
     - request headers, **only** those in ``headers_allowlist`` (a duplicated header is absent)

Everything except the built-ins must be **declared in the catalog**
(see :ref:`authz-catalog`); a policy that names an undeclared attribute, compares incompatible types or
uses a literal outside an ``enum`` is rejected when written. Attributes are loaded **lazily**: a loader is
called only if an applicable policy reads ``resource.attrs.*``, and at most once per decision.

Wiring it
---------

.. literalinclude:: ../examples/abac_example.py
   :language: python
   :start-at: config = AbacConfig(
   :end-before: app = FastAPI()

.. literalinclude:: ../examples/abac_example.py
   :language: python
   :start-at: @app.delete(
   :end-before: @app.get(

``resource=`` takes a ``ResourceFromPath``, ``ResourceFromQuery`` or ``ResourceFromCallable`` (use the
callable when the id is in the body, and read the body yourself: the library never consumes it).
A loader returns the resource's attributes, or ``None`` when it does not exist, which is answered exactly
like a non-member (404). A loader that raises is an outage (503), never an allow.
Inside a handler use ``has_permission(request, "design.delete", scope, resource=...)``.

A guard with ``resource=`` on an app whose ``Authz`` has no ``abac=`` is a **startup error** (it would
otherwise be ignored). Static policies that read a header or a claim nobody allow-listed also fail at
build: such an attribute is always absent, so a ``deny`` on it would deny every request.

Cookbook
--------

The five policies of ``examples/abac_policies.toml`` (the example application loads exactly this file, and
the test suite validates it):

.. literalinclude:: ../examples/abac_policies.toml
   :language: toml

Persistence
-----------

Policies and attributes use the same engines and the same pattern as the assignments: optimistic
``revision``, ``StoreUnavailableError`` on outages, no new extra.

SQLAlchemy
~~~~~~~~~~

``SqlPolicyStore`` and ``SqlAttributeStore`` accept the three session shapes of ``SqlAssignmentStore``
(a sessionmaker, a callable returning an async context manager, or an open session) and the
``before_query`` hook for row-level security. The tables ``authz_policy`` and ``authz_attribute`` come from
the Alembic revision ``b7d2e5f1c3a8`` (``alembic upgrade head``); it only adds those two tables.
The JSON columns are ``JSONB`` on PostgreSQL. ``condition`` is stored in ``condition_doc`` (it is a reserved
word in MySQL).

DynamoDB
~~~~~~~~

``DynamoDbPolicyStore`` and ``DynamoDbAttributeStore`` (PynamoDB) use a table with ``pk``/``sk`` and **no
index**:

.. code-block:: text

   Policy       pk=SCOPE#<kind>#<scope id | *>   sk=POLICY#<policy id>
   Id marker    pk=POLICYID#<policy id>          sk=META
   Attributes   pk=ENTITY#<ns>#<kind>#<id>       sk=ATTRS

``list_policies`` is two consistent ``Query`` calls (the scope's partition and the kind-wide ``*`` one).
The *id marker* makes ids unique across scopes. ``DynamoDbPolicyStore.table_definition(name)`` returns the
``create_table`` arguments; the IAM policy needs ``GetItem``, ``PutItem``, ``UpdateItem``, ``DeleteItem``,
``Query`` and (for ``list_all`` / ``authcli authz policy list`` only) ``Scan``.

Managing policies
-----------------

Write through ``PolicyService`` so nothing invalid reaches the store; it validates against the catalog,
serialises writes per policy id and runs ``after_change`` hooks:

.. code-block:: python

   service = PolicyService(store, catalog, after_change=[cache.on_change])
   policy = await service.create(NewPolicy(...))
   await service.replace(policy.id, NewPolicy(...), expected_revision=policy.revision)
   await service.disable(policy.id, expected_revision=...)

The CLI does the same from a shell (``AUTHZ_SQLALCHEMY_DATABASE_URI`` or ``AUTHZ_POLICY_TABLE`` and
``AUTHZ_DYNAMODB_ENDPOINT`` select the store):

.. code-block:: console

   $ authcli authz policy validate --file policy.json --catalog catalog.toml       # offline
   $ authcli authz policy test --file policy.json --context ctx.json               # offline
   condition: INDETERMINATE
   missing attributes: subject.assignment.tenant_status
   effect deny: would DENY (indeterminate fails closed)
   $ authcli authz policy add --store sqlalchemy --file policy.json --catalog catalog.toml
   $ authcli authz policy list --store sqlalchemy --all
   $ authcli authz policy disable ID --store sqlalchemy --expected-revision 0

Static policies (``StaticPolicySource.from_file``) and stored ones can be combined
(``AbacConfig(policies=[static, store])``): an id defined twice fails at startup.

.. _abac-rollout:

Rolling a policy out safely
---------------------------

1. ``authcli authz policy test`` the condition against representative contexts.
2. Add it with ``enforce = false`` (shadow mode).
3. Watch ``shadow_policy_ids`` in the audit events (and the ``shadow_denied`` counter) for a few days:
   those are the requests it *would* have denied.
4. Flip it with ``replace`` and ``enforce = true``.

Operations
----------

Policy cache
~~~~~~~~~~~~

The policies of a scope are cached **5 seconds** by default (``AbacConfig.policy_cache_ttl``; ``0``
disables it). Changes written through ``PolicyService`` in the same process show immediately; **other
processes see a change only after the TTL**. Failed loads are not cached and an expired entry is never
served when the reload fails (503). Assignments, unlike policies, are never cached unless you ask.

Audit, metrics, explain
~~~~~~~~~~~~~~~~~~~~~~~

``DecisionEvent`` gains ``policy_ids`` (the policies that decided), ``shadow_policy_ids`` and
``abac_reason`` (``deny:<id>``, ``require:<id>``, ``indeterminate:<id>``, ``permit:<id>``): **ids only,
never attribute values**. ``metrics_hook`` counts decisions per source (``by_source``) and per policy
(``abac_policies``, at most 100 ids, the rest under ``other``).

``Authorizer.explain(principal, permission, scope, resource=...)`` evaluates every policy and reports why
(values are left out unless ``reveal=True``). It is for logs and tools: never put it in an HTTP response.

Fail closed
~~~~~~~~~~~

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - What goes wrong
     - Answer
   * - policy source down, slow or returns garbage
     - 503, never 200
   * - attribute provider or resource loader raises
     - 503
   * - resource loader returns ``None``
     - 404 (same as a non-member)
   * - an attribute is missing or of the wrong type
     - ``deny`` applies, ``require`` is not satisfied
   * - a stored policy cannot be decoded
     - behaves as a ``deny`` of the permissions it names
   * - a loader returns a value that is huge or of an unsupported type
     - that value is dropped (the attribute is missing)

Expressing a tenant-status gate
-------------------------------

An application that hard-codes "the tenant is suspended, so no writes" in every handler can express it
once: store the status in the assignment's ``attributes`` (or in ``resource.attrs`` through a loader) and
add the first policy of the cookbook. The roles keep saying who may write; the policy says when.

Not covered (yet)
-----------------

Pushing a policy into a list query ("partial evaluation"), obligations, delegation, an HTTP API to manage
policies and distributed cache invalidation are out of scope for this release.
