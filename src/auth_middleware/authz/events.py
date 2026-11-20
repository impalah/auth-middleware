"""Hooks that turn authorization decisions into audit logs and metrics."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

from auth_middleware.authz.runtime import DecisionEvent
from auth_middleware.authz.types import DecisionKind
from auth_middleware.services.audit import AuditEvent, AuditLogger
from auth_middleware.services.metrics import MetricsCollector


def _level(event: DecisionEvent) -> int:
    if event.kind is DecisionKind.DENIED:
        return logging.WARNING
    if event.kind is DecisionKind.NOT_VISIBLE or event.sensitive:
        return logging.INFO
    if event.shadow_policy_ids:  # allowed, but a shadow policy would have denied
        return logging.INFO
    return logging.DEBUG


def audit_hook(audit: AuditLogger) -> Callable[[DecisionEvent], None]:
    """Build an ``on_decision`` hook that logs through ``AuditLogger``.

    Levels: ``DENIED`` WARNING, ``NOT_VISIBLE`` INFO, ``ALLOWED`` DEBUG, except
    ``sensitive`` permissions and decisions a shadow (``enforce=false``) policy
    would have denied, which log at INFO even when allowed. Events carry ids and
    permission names only (ABAC: policy ids and the reason, never attribute values).

    Args:
        audit: The library's audit logger (its callback is invoked too).
    """

    def hook(event: DecisionEvent) -> None:
        data = event.to_dict()
        audit_event = AuditEvent(
            event_type="authz",
            user_id=event.principal_id,
            **{k: v for k, v in data.items() if k != "principal_id"},
        )
        if audit.log_to_console:
            audit.logger.log(
                _level(event),
                "AUDIT: authz",
                extra={"audit_event": audit_event.to_dict()},
            )
        if audit.log_callback:
            audit.log_callback(audit_event)

    return hook


def metrics_hook(
    collector: MetricsCollector,
) -> Callable[[DecisionEvent], Awaitable[None]]:
    """Build an ``on_decision`` hook counting decisions per kind and permission.

    Without ABAC the counters are exactly the 0.7.0 ones. With policies involved
    the decision is also counted under ``by_source`` and each policy under
    ``abac_policies`` (``denied``, ``permitted`` or ``shadow_denied``).
    """

    async def hook(event: DecisionEvent) -> None:
        abac = bool(event.policy_ids or event.shadow_policy_ids)
        await collector.record_authz_decision(
            event.kind.value,
            event.permission,
            source=("abac" if event.policy_ids else "rbac") if abac else None,
        )
        decided = "permitted" if event.kind is DecisionKind.ALLOWED else "denied"
        for policy_id in event.policy_ids:
            await collector.record_abac_policy(policy_id, decided)
        for policy_id in event.shadow_policy_ids:
            await collector.record_abac_policy(policy_id, "shadow_denied")

    return hook


def combine_hooks(
    *hooks: Callable[[DecisionEvent], Awaitable[None] | None],
) -> Callable[[DecisionEvent], Awaitable[None]]:
    """Run several hooks in order (each may be sync or async)."""
    import inspect

    async def hook(event: DecisionEvent) -> None:
        for h in hooks:
            result = h(event)
            if inspect.isawaitable(result):
                await result

    return hook
