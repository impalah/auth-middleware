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
    return logging.DEBUG


def audit_hook(audit: AuditLogger) -> Callable[[DecisionEvent], None]:
    """Build an ``on_decision`` hook that logs through ``AuditLogger``.

    Levels: ``DENIED`` WARNING, ``NOT_VISIBLE`` INFO, ``ALLOWED`` DEBUG, except
    ``sensitive`` permissions which log at INFO even when allowed. Events carry
    ids and permission names only.

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
    """Build an ``on_decision`` hook counting decisions per kind and permission."""

    async def hook(event: DecisionEvent) -> None:
        await collector.record_authz_decision(event.kind.value, event.permission)

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
