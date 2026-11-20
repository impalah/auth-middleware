"""Attribute-based access control (ABAC) on top of scoped permissions.

The package is imported lazily by ``auth_middleware.authz``: with no policy
configured none of it runs. Names are resolved on first access so importing
this package stays cheap and free of cycles.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # lets type checkers see the lazy exports
    from auth_middleware.authz.abac.attributes import (
        AttributeProvider as AttributeProvider,
    )
    from auth_middleware.authz.abac.attributes import (
        AttributeRequest as AttributeRequest,
    )
    from auth_middleware.authz.abac.attributes import (
        AttributeResolver as AttributeResolver,
    )
    from auth_middleware.authz.abac.attributes import (
        ContextAttributeProvider as ContextAttributeProvider,
    )
    from auth_middleware.authz.abac.attributes import (
        EnvironmentProvider as EnvironmentProvider,
    )
    from auth_middleware.authz.abac.attributes import (
        ResourceAttributeProvider as ResourceAttributeProvider,
    )
    from auth_middleware.authz.abac.attributes import (
        ResourceContext as ResourceContext,
    )
    from auth_middleware.authz.abac.attributes import (
        ResourceRef as ResourceRef,
    )
    from auth_middleware.authz.abac.attributes import (
        SubjectAttributeProvider as SubjectAttributeProvider,
    )
    from auth_middleware.authz.abac.cache import (
        CachingPolicySource as CachingPolicySource,
    )
    from auth_middleware.authz.abac.conditions import (
        ABSENT as ABSENT,
    )
    from auth_middleware.authz.abac.conditions import (
        Condition as Condition,
    )
    from auth_middleware.authz.abac.conditions import (
        ConditionLimits as ConditionLimits,
    )
    from auth_middleware.authz.abac.conditions import (
        Tri as Tri,
    )
    from auth_middleware.authz.abac.conditions import (
        cond_to_dict as cond_to_dict,
    )
    from auth_middleware.authz.abac.conditions import (
        evaluate as evaluate,
    )
    from auth_middleware.authz.abac.conditions import (
        parse_condition as parse_condition,
    )
    from auth_middleware.authz.abac.config import (
        AbacConfig as AbacConfig,
    )
    from auth_middleware.authz.abac.pdp import (
        AbacOutcome as AbacOutcome,
    )
    from auth_middleware.authz.abac.pdp import (
        Explanation as Explanation,
    )
    from auth_middleware.authz.abac.pdp import (
        PolicyDecisionPoint as PolicyDecisionPoint,
    )
    from auth_middleware.authz.abac.pdp import (
        PolicyTrace as PolicyTrace,
    )
    from auth_middleware.authz.abac.resources import (
        ResourceFromCallable as ResourceFromCallable,
    )
    from auth_middleware.authz.abac.resources import (
        ResourceFromPath as ResourceFromPath,
    )
    from auth_middleware.authz.abac.resources import (
        ResourceFromQuery as ResourceFromQuery,
    )
    from auth_middleware.authz.abac.resources import (
        ResourceSource as ResourceSource,
    )
    from auth_middleware.authz.abac.schema import (
        BUILTIN_ATTRIBUTES as BUILTIN_ATTRIBUTES,
    )
    from auth_middleware.authz.abac.schema import (
        AttributeSchema as AttributeSchema,
    )
    from auth_middleware.authz.abac.schema import (
        AttributeSpec as AttributeSpec,
    )
    from auth_middleware.authz.abac.service import (
        PolicyChange as PolicyChange,
    )
    from auth_middleware.authz.abac.service import (
        PolicyService as PolicyService,
    )
    from auth_middleware.authz.abac.sources import (
        CompositePolicySource as CompositePolicySource,
    )
    from auth_middleware.authz.abac.sources import (
        StaticPolicySource as StaticPolicySource,
    )
    from auth_middleware.authz.abac.types import (
        Effect as Effect,
    )
    from auth_middleware.authz.abac.types import (
        EntityAttributes as EntityAttributes,
    )
    from auth_middleware.authz.abac.types import (
        EntityRef as EntityRef,
    )
    from auth_middleware.authz.abac.types import (
        NewPolicy as NewPolicy,
    )
    from auth_middleware.authz.abac.types import (
        Policy as Policy,
    )
    from auth_middleware.authz.abac.types import (
        PolicyScope as PolicyScope,
    )
    from auth_middleware.authz.abac.types import (
        PolicyStatus as PolicyStatus,
    )
    from auth_middleware.authz.abac.types import (
        validate_attributes as validate_attributes,
    )
    from auth_middleware.authz.abac.validation import (
        policy_matches_permission as policy_matches_permission,
    )
    from auth_middleware.authz.abac.validation import (
        validate_policy as validate_policy,
    )

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
__all__ = [
    "ABSENT",
    "AbacConfig",
    "AbacOutcome",
    "AttributeProvider",
    "AttributeRequest",
    "AttributeResolver",
    "AttributeSchema",
    "AttributeSpec",
    "BUILTIN_ATTRIBUTES",
    "CachingPolicySource",
    "CompositePolicySource",
    "Condition",
    "ConditionLimits",
    "ContextAttributeProvider",
    "Effect",
    "EntityAttributes",
    "EntityRef",
    "EnvironmentProvider",
    "Explanation",
    "NewPolicy",
    "Policy",
    "PolicyChange",
    "PolicyDecisionPoint",
    "PolicyScope",
    "PolicyService",
    "PolicyStatus",
    "PolicyTrace",
    "ResourceAttributeProvider",
    "ResourceContext",
    "ResourceFromCallable",
    "ResourceFromPath",
    "ResourceFromQuery",
    "ResourceRef",
    "ResourceSource",
    "StaticPolicySource",
    "SubjectAttributeProvider",
    "Tri",
    "cond_to_dict",
    "evaluate",
    "parse_condition",
    "policy_matches_permission",
    "validate_attributes",
    "validate_policy",
]


def __getattr__(name: str) -> Any:
    mod = _LOOKUP.get(name)
    if mod is None:
        raise AttributeError(name)
    return getattr(import_module(f"{__name__}.{mod}"), name)
