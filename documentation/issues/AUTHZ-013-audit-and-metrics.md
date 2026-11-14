# AUTHZ-013 · Audit events and metrics

Epic D · Size S · Depends on: 004

## Context

The library already has `services/audit.py` (an `AuditEvent` and an audit middleware) and
`services/metrics.py`. Read both first and extend, do not duplicate. ARTISEVM logs structured JSON in
production and correlates by request id; it must not log tokens or e-mails.

## Scope

`src/auth_middleware/authz/events.py`, wiring in `runtime.py`/`guards.py` through the `AuthzHooks`
type created in AUTHZ-004, tests `tests/authz/test_events.py`.

## Design

```python
@dataclass(frozen=True, slots=True)
class DecisionEvent:
    kind: DecisionKind  # ALLOWED / NOT_VISIBLE / DENIED
    principal_id: str
    scope: ScopeRef
    permission: str
    roles: frozenset[str]  # empty for NOT_VISIBLE
    sensitive: bool  # from the catalog
    duration_ms: float
    request_id: (
        str | None
    )  # from request.state.correlation_id / X-Request-ID when present
```

- The guard builds the event after every decision and awaits `hooks.on_decision` (sync or async). A
  hook that raises is **logged and swallowed**: auditing must never turn an allowed request into a 500
  (document that choice; an application that needs fail-closed auditing wraps its own dependency).
- Provide `audit_hook(logger)` that emits through the existing `AuditEvent` machinery with
  `event_type="authz"`, and `metrics_hook(...)` that increments counters per kind and per permission
  using the existing `services/metrics.py` facilities. Look at how that module exposes counters and
  follow it; if it cannot take labels, add a minimal, backwards compatible extension.
- Privacy: events carry ids and permission names only. Add a test that serialises an event and asserts
  no e-mail, token or claim values appear.
- `sensitive=True` permissions are logged at INFO even when allowed; others log allowed decisions at
  DEBUG and denials at INFO/WARNING (NOT_VISIBLE at INFO, DENIED at WARNING).

## Acceptance criteria

- [ ] Hook called once per decision with the right kind; exceptions in the hook do not change the response.
- [ ] Event for a `NOT_VISIBLE` outcome carries no roles and does not reveal whether the scope exists
  beyond what the caller sent.
- [ ] Metrics counters increment per outcome in a test using the existing metrics module.
- [ ] Privacy test above.

## Out of scope

Shipping logs anywhere; a metrics exporter.
