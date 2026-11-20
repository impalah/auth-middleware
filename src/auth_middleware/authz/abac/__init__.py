"""Attribute-based access control (ABAC) on top of scoped permissions.

The package is imported lazily by ``auth_middleware.authz``: with no policy
configured none of it runs. Names are resolved on first access so importing
this package stays cheap and free of cycles.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_EXPORTS = {
    "types": (
        "Effect",
        "PolicyStatus",
        "PolicyScope",
        "Policy",
        "NewPolicy",
        "EntityRef",
        "EntityAttributes",
        "validate_attributes",
    ),
    "conditions": (
        "ABSENT",
        "Tri",
        "Condition",
        "ConditionLimits",
        "parse_condition",
        "cond_to_dict",
        "evaluate",
    ),
    "schema": ("AttributeSpec", "AttributeSchema", "BUILTIN_ATTRIBUTES"),
    "validation": ("validate_policy", "policy_matches_permission"),
    "attributes": (
        "ResourceRef",
        "ResourceContext",
        "AttributeRequest",
        "AttributeProvider",
        "AttributeResolver",
        "ContextAttributeProvider",
        "SubjectAttributeProvider",
        "ResourceAttributeProvider",
        "EnvironmentProvider",
    ),
    "resources": (
        "ResourceSource",
        "ResourceFromPath",
        "ResourceFromQuery",
        "ResourceFromCallable",
    ),
    "pdp": ("PolicyDecisionPoint", "AbacOutcome", "PolicyTrace", "Explanation"),
    "sources": ("StaticPolicySource", "CompositePolicySource"),
    "cache": ("CachingPolicySource",),
    "service": ("PolicyService", "PolicyChange"),
    "config": ("AbacConfig",),
}
_LOOKUP = {name: mod for mod, names in _EXPORTS.items() for name in names}
__all__ = sorted(_LOOKUP)  # noqa: PLE0605  (computed on purpose)


def __getattr__(name: str) -> Any:
    mod = _LOOKUP.get(name)
    if mod is None:
        raise AttributeError(name)
    return getattr(import_module(f"{__name__}.{mod}"), name)
