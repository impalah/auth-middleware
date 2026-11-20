"""``AbacConfig``: the ABAC part of ``Authz.build`` (nothing reads the environment)."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from auth_middleware.authz.abac.attributes import AttributeProvider, AttributeResolver
from auth_middleware.authz.abac.cache import CachingPolicySource
from auth_middleware.authz.abac.conditions import condition_paths, parse_condition
from auth_middleware.authz.abac.pdp import Mode, PolicyDecisionPoint
from auth_middleware.authz.abac.sources import CompositePolicySource, StaticPolicySource
from auth_middleware.authz.abac.validation import validate_policy
from auth_middleware.authz.catalog import PermissionCatalog
from auth_middleware.authz.errors import ConfigurationError, InvalidPolicyError
from auth_middleware.authz.ports import AttributeStore, PolicyStore


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class AbacConfig:
    """Attribute-based access control settings.

    Args:
        policies: One policy source or several (static files, stores...); several
            are read as one (earlier wins on a clashing id).
        attributes: Persisted principal/resource attributes (optional).
        mode: ``restrict`` (policies only narrow what roles grant; default) or
            ``grant`` (``permit`` policies may grant; experimental).
        policy_cache_ttl: Seconds the policies of a scope are cached (default 5;
            ``0`` disables the cache). Other processes see a change only after it.
        claims_allowlist: Token claims policies may read.
        headers_allowlist: Request headers policies may read.
        trusted_proxies: CIDRs whose ``X-Forwarded-For`` is believed.
        clock: Aware-``datetime`` clock for ``env.now`` (inject in tests).
        providers: Extra attribute providers (disjoint path prefixes).
    """

    policies: PolicyStore | Sequence[PolicyStore]
    attributes: AttributeStore | None = None
    mode: Mode = "restrict"
    policy_cache_ttl: float = 5.0
    claims_allowlist: Mapping[str, str] | Sequence[str] = ()
    headers_allowlist: Iterable[str] = ()
    trusted_proxies: Iterable[str] = ()
    clock: Callable[[], datetime] = field(default=_utcnow)
    providers: Sequence[AttributeProvider] = ()

    def sources(self) -> tuple[PolicyStore, ...]:
        """The configured sources as a tuple."""
        if isinstance(self.policies, Sequence):
            return tuple(self.policies)
        return (self.policies,)

    def build(
        self, catalog: PermissionCatalog
    ) -> tuple[PolicyDecisionPoint, PolicyStore]:
        """Validate the static policies and build the decision point.

        Returns:
            ``(pdp, policy_source)``; the source is what the cache wraps.

        Raises:
            ConfigurationError: Invalid mode/cache or invalid static policies (every
                problem is listed).
        """
        if self.mode not in ("restrict", "grant"):
            raise ConfigurationError(f"unknown ABAC mode: {self.mode!r}")
        if self.policy_cache_ttl < 0:
            raise ConfigurationError("policy_cache_ttl must be >= 0")
        sources = self.sources()
        if not sources:
            raise ConfigurationError("abac needs at least one policy source")
        self._validate_static(sources, catalog)
        source: PolicyStore = (
            sources[0] if len(sources) == 1 else CompositePolicySource(*sources)
        )
        if self.policy_cache_ttl > 0:
            source = CachingPolicySource(source, ttl_seconds=self.policy_cache_ttl)
        resolver = AttributeResolver.default(
            attributes=self.attributes,
            claims_allowlist=self.claims_allowlist,
            headers_allowlist=self.headers_allowlist,
            trusted_proxies=self.trusted_proxies,
            clock=self.clock,
            extra=self.providers,
        )
        return PolicyDecisionPoint(source, resolver, mode=self.mode), source

    def _validate_static(
        self, sources: Sequence[PolicyStore], catalog: PermissionCatalog
    ) -> None:
        problems: list[str] = []
        for source in sources:
            if not isinstance(source, StaticPolicySource):
                continue
            for policy in source.policies:
                try:
                    validate_policy(policy, catalog, allow_permit=self.mode == "grant")
                except InvalidPolicyError as exc:
                    problems.extend(exc.problems if exc.problems else [str(exc)])
        problems.extend(self._unreachable_attributes(sources))
        if problems:
            raise ConfigurationError("invalid static policies: " + "; ".join(problems))

    def _unreachable_attributes(self, sources: Sequence[PolicyStore]) -> list[str]:
        """Static policies reading headers/claims nobody allow-listed.

        Such an attribute is always absent, so a ``deny`` on it would deny every
        request (indeterminate fails closed): better a startup error than an outage.
        """
        headers = {h.strip().lower().replace("_", "-") for h in self.headers_allowlist}
        claims = set(self.claims_allowlist)  # a mapping contributes its keys
        problems: list[str] = []
        for source in sources:
            if not isinstance(source, StaticPolicySource):
                continue
            for policy in source.policies:
                for path in sorted(condition_paths(parse_condition(policy.condition))):
                    if path.startswith("env.header."):
                        name = path.removeprefix("env.header.").replace("_", "-")
                        if name not in headers:
                            problems.append(
                                f"policy {policy.id!r} reads {path}, which is not in "
                                "headers_allowlist"
                            )
                    elif path.startswith("subject.claims."):
                        segment = path.removeprefix("subject.claims.").split(".")[0]
                        if segment not in claims:
                            problems.append(
                                f"policy {policy.id!r} reads {path}, which is not in "
                                "claims_allowlist"
                            )
        return problems


__all__: list[Any] = ["AbacConfig"]
