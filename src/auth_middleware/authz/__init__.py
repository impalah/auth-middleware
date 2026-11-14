"""Scoped permissions: catalog, engine, stores and FastAPI guard."""

from __future__ import annotations

from auth_middleware.authz.cache import CachingAssignmentStore
from auth_middleware.authz.catalog import PermissionCatalog, PermissionSpec, ScopeKind
from auth_middleware.authz.engine import Authorizer
from auth_middleware.authz.errors import (
    AuthzError,
    CatalogError,
    ConfigurationError,
    PermissionDeniedError,
    RevisionConflictError,
    ScopeKindMismatchError,
    ScopeNotVisibleError,
    StoreUnavailableError,
    UnknownPermissionError,
    UnknownRoleError,
)
from auth_middleware.authz.guards import has_permission, require_permission
from auth_middleware.authz.openapi import declared_permissions, permission_extra
from auth_middleware.authz.ports import AssignmentAdmin, AssignmentStore, StoreFactory
from auth_middleware.authz.resolvers import (
    AssignmentRoleResolver,
    GroupRoleResolver,
    ResolvedRoles,
    RoleResolver,
)
from auth_middleware.authz.runtime import (
    Authz,
    AuthzHooks,
    DecisionEvent,
    ErrorPolicy,
)
from auth_middleware.authz.scopes import (
    GlobalScope,
    ScopeFromCallable,
    ScopeFromPath,
    ScopeSource,
)
from auth_middleware.authz.service import AssignmentChange, AssignmentService
from auth_middleware.authz.types import (
    GLOBAL_KIND,
    Assignment,
    AssignmentStatus,
    AuthzContext,
    DecisionKind,
    NewAssignment,
    Principal,
    ScopeRef,
)

__all__ = [
    "AssignmentRoleResolver",
    "Authorizer",
    "Authz",
    "AuthzHooks",
    "DecisionEvent",
    "ErrorPolicy",
    "GlobalScope",
    "GroupRoleResolver",
    "PermissionCatalog",
    "PermissionSpec",
    "ResolvedRoles",
    "RoleResolver",
    "ScopeFromCallable",
    "ScopeFromPath",
    "ScopeKind",
    "ScopeSource",
    "declared_permissions",
    "has_permission",
    "permission_extra",
    "require_permission",
    "GLOBAL_KIND",
    "Assignment",
    "AssignmentChange",
    "AssignmentService",
    "AssignmentAdmin",
    "AssignmentStatus",
    "AssignmentStore",
    "AuthzContext",
    "AuthzError",
    "CachingAssignmentStore",
    "CatalogError",
    "ConfigurationError",
    "DecisionKind",
    "NewAssignment",
    "PermissionDeniedError",
    "Principal",
    "RevisionConflictError",
    "ScopeKindMismatchError",
    "ScopeNotVisibleError",
    "ScopeRef",
    "StoreFactory",
    "StoreUnavailableError",
    "UnknownPermissionError",
    "UnknownRoleError",
]
