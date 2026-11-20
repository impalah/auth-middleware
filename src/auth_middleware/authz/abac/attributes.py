"""Attribute providers: where each namespace of the condition language comes from.

Providers are lazy (they only load what the applicable policies read), run one
after the other (stores may share a database session) and own disjoint path
prefixes: nobody can override another provider's attributes.
"""

from __future__ import annotations

import inspect
import ipaddress
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from loguru import logger

from auth_middleware.authz.abac.types import EntityRef, validate_attributes
from auth_middleware.authz.errors import (
    AuthzError,
    ConfigurationError,
    InvalidPolicyError,
    ResourceNotFoundError,
    StoreUnavailableError,
)
from auth_middleware.authz.ports import AttributeStore
from auth_middleware.authz.types import MAX_ID_LENGTH, Principal, ScopeRef

if TYPE_CHECKING:
    from starlette.requests import Request

_KIND_RE = re.compile(r"[a-z][a-z0-9_]*")
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True, slots=True)
class ResourceRef:
    """The resource a request is about: a kind and an id."""

    kind: str
    id: str

    def __post_init__(self) -> None:
        if not _KIND_RE.fullmatch(self.kind):
            raise ValueError(f"invalid resource kind: {self.kind!r}")
        if not self.id or len(self.id) > MAX_ID_LENGTH:
            raise ValueError("invalid resource id")


ResourceLoader = Callable[
    ["Request | None", ResourceRef],
    "Awaitable[Mapping[str, Any] | None] | Mapping[str, Any] | None",
]
"""``loader(request, ref) -> attributes | None`` (``None``: no such resource)."""


@dataclass(frozen=True, slots=True)
class ResourceContext:
    """A resolved resource plus the (optional) loader of its attributes."""

    ref: ResourceRef
    loader: ResourceLoader | None = None


@dataclass(frozen=True, slots=True)
class AttributeRequest:
    """Everything a provider may need to answer for one decision."""

    principal: Principal
    permission: str
    scope: ScopeRef
    roles: frozenset[str] = frozenset()
    assignment_attributes: Mapping[str, Any] | None = None
    resource: ResourceContext | None = None
    request: Request | None = None


class AttributeProvider(Protocol):
    """Loads the attributes under some path prefixes."""

    #: Exact paths (``subject.id``) or prefixes ending in a dot (``subject.attrs.``).
    prefixes: tuple[str, ...]

    async def load(
        self, ctx: AttributeRequest, needed: frozenset[str]
    ) -> Mapping[str, Any]:
        """Return ``path -> value`` for the ``needed`` paths it can answer."""
        ...


def _handles(prefix: str, path: str) -> bool:
    return path == prefix or (prefix.endswith(".") and path.startswith(prefix))


def _overlap(a: str, b: str) -> bool:
    return _handles(a, b) or _handles(b, a)


def _dig(data: Any, parts: Sequence[str]) -> Any:
    """Walk nested mappings; ``_MISSING`` when any step is absent."""
    for part in parts:
        if not isinstance(data, Mapping) or part not in data:
            return _MISSING
        data = data[part]
    return data


class _Missing:
    __slots__ = ()


_MISSING = _Missing()


def _clean(value: Any) -> Any:
    """A safe copy of one attribute value, or ``_MISSING`` when it is not usable."""
    try:
        return validate_attributes({"v": value})["v"]
    except InvalidPolicyError:
        return _MISSING


def _pick(
    source: Any,
    prefix: str,
    needed: frozenset[str],
    *,
    only: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Answer every needed path below ``prefix`` from a nested mapping."""
    found: dict[str, Any] = {}
    for path in needed:
        if not path.startswith(prefix):
            continue
        parts = path[len(prefix) :].split(".")
        if only is not None and parts[0] not in only:
            continue
        value = _dig(source, parts)
        if value is not _MISSING:
            cleaned = _clean(value)
            if cleaned is not _MISSING:
                found[path] = cleaned
    return found


class ContextAttributeProvider:
    """``subject.id|email|groups|roles|claims.*|assignment.*``, ``action.permission``,
    ``resource.kind|id``: everything the decision already knows."""

    prefixes: tuple[str, ...] = (
        "subject.id",
        "subject.email",
        "subject.groups",
        "subject.roles",
        "subject.claims.",
        "subject.assignment.",
        "action.permission",
        "resource.kind",
        "resource.id",
    )

    def __init__(
        self, claims_allowlist: Mapping[str, str] | Sequence[str] = ()
    ) -> None:
        """
        Args:
            claims_allowlist: Token claims policies may read. A sequence of claim
                names that are valid path segments, or ``{segment: claim_name}``
                for names that are not (``{"dept": "custom:department"}``).
        """
        if isinstance(claims_allowlist, Mapping):
            allowed = dict(claims_allowlist)
        else:
            allowed = {name: name for name in claims_allowlist}
        for segment in allowed:
            if not _NAME_RE.fullmatch(segment):
                raise ConfigurationError(f"invalid claim segment: {segment!r}")
        self._claims = allowed

    async def load(
        self, ctx: AttributeRequest, needed: frozenset[str]
    ) -> Mapping[str, Any]:
        p = ctx.principal
        known: dict[str, Any] = {
            "subject.id": p.id,
            "subject.groups": list(p.groups),
            "subject.roles": sorted(ctx.roles),
            "action.permission": ctx.permission,
        }
        if p.email is not None:
            known["subject.email"] = p.email
        if ctx.resource is not None:
            known["resource.kind"] = ctx.resource.ref.kind
            known["resource.id"] = ctx.resource.ref.id
        found = {k: v for k, v in known.items() if k in needed}
        found.update(
            _pick(ctx.assignment_attributes or {}, "subject.assignment.", needed)
        )
        claims = _claims_of(ctx.request)
        if claims is not None and self._claims:
            renamed = {
                seg: claims[name]
                for seg, name in self._claims.items()
                if name in claims
            }
            found.update(
                _pick(renamed, "subject.claims.", needed, only=frozenset(self._claims))
            )
        return found


def _claims_of(request: Request | None) -> Mapping[str, Any] | None:
    user = getattr(getattr(request, "state", None), "current_user", None)
    creds = getattr(user, "_jwt_credentials", None)
    claims = getattr(creds, "claims", None)
    return claims if isinstance(claims, Mapping) else None


class SubjectAttributeProvider:
    """``subject.attrs.*`` from the persisted principal attributes."""

    prefixes: tuple[str, ...] = ("subject.attrs.",)

    def __init__(self, store: AttributeStore | None = None) -> None:
        self._store = store

    async def load(
        self, ctx: AttributeRequest, needed: frozenset[str]
    ) -> Mapping[str, Any]:
        if self._store is None:
            return {}
        try:
            stored = await self._store.get_attributes(
                EntityRef.principal(ctx.principal.id)
            )
        except AuthzError:
            raise
        except Exception as exc:
            raise StoreUnavailableError("attribute store failed") from exc
        if stored is None:
            return {}
        return _pick(stored.attributes, "subject.attrs.", needed)


class ResourceAttributeProvider:
    """``resource.attrs.*``: the route's loader first, else the persisted attributes.

    A loader answering ``None`` means "no such resource": the decision is then
    "not visible", the same answer as for a non-member. A loader that raises is an
    outage (the guard answers 503), never an allow.
    """

    prefixes: tuple[str, ...] = ("resource.attrs.",)

    def __init__(self, store: AttributeStore | None = None) -> None:
        self._store = store

    async def load(
        self, ctx: AttributeRequest, needed: frozenset[str]
    ) -> Mapping[str, Any]:
        res = ctx.resource
        if res is None:
            return {}
        if res.loader is not None:
            data = await self._run_loader(res, ctx.request)
        elif self._store is not None:
            data = await self._read_store(res.ref)
        else:
            return {}
        return _pick(data, "resource.attrs.", needed)

    async def _run_loader(
        self, res: ResourceContext, request: Request | None
    ) -> Mapping[str, Any]:
        assert res.loader is not None  # noqa: S101 - narrowed by the caller
        try:
            data = res.loader(request, res.ref)
            if inspect.isawaitable(data):
                data = await data
        except AuthzError:
            raise
        except Exception as exc:
            logger.opt(exception=True).error("resource loader failed")
            raise StoreUnavailableError("resource loader failed") from exc
        if data is None:
            raise ResourceNotFoundError(res.ref.kind)
        if not isinstance(data, Mapping):
            raise StoreUnavailableError("resource loader returned a non-mapping")
        return data

    async def _read_store(self, ref: ResourceRef) -> Mapping[str, Any]:
        assert self._store is not None  # noqa: S101
        try:
            stored = await self._store.get_attributes(
                EntityRef("resource", ref.kind, ref.id)
            )
        except AuthzError:
            raise
        except Exception as exc:
            raise StoreUnavailableError("attribute store failed") from exc
        return {} if stored is None else stored.attributes


def _networks(
    proxies: Iterable[str],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    try:
        return tuple(ipaddress.ip_network(p, strict=False) for p in proxies)
    except ValueError as exc:
        raise ConfigurationError(f"invalid trusted proxy: {exc}") from None


def _norm_header(name: str) -> str:
    return name.strip().lower().replace("_", "-")


class EnvironmentProvider:
    """``env.now|hour_utc|weekday|method|path|ip|header.<name>``."""

    prefixes: tuple[str, ...] = ("env.",)

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        headers_allowlist: Iterable[str] = (),
        trusted_proxies: Iterable[str] = (),
    ) -> None:
        """
        Args:
            clock: Returns an aware ``datetime`` (inject a fake in tests).
            headers_allowlist: Header names policies may read (case-insensitive;
                ``x_tenant`` and ``x-tenant`` are the same).
            trusted_proxies: CIDR networks whose ``X-Forwarded-For`` is believed.
                Empty: the header is ignored and ``env.ip`` is the TCP peer.
        """
        self._clock = clock
        self._headers = frozenset(_norm_header(h) for h in headers_allowlist)
        self._proxies = _networks(trusted_proxies)

    def _client_ip(self, request: Request) -> str | None:
        peer = request.client.host if request.client else None
        try:
            addr = ipaddress.ip_address(peer) if peer else None
        except ValueError:
            return None
        if addr is None or not any(addr in net for net in self._proxies):
            return None if addr is None else str(addr)
        forwarded = request.headers.get("x-forwarded-for", "")
        for hop in reversed([h.strip() for h in forwarded.split(",") if h.strip()]):
            try:
                candidate = ipaddress.ip_address(hop)
            except ValueError:
                return None
            if not any(candidate in net for net in self._proxies):
                return str(candidate)
        return str(addr)

    def _header(self, request: Request, name: str) -> str | None:
        if name not in self._headers:
            return None
        values = request.headers.getlist(name)
        return values[0] if len(values) == 1 else None

    async def load(
        self, ctx: AttributeRequest, needed: frozenset[str]
    ) -> Mapping[str, Any]:
        found: dict[str, Any] = {}
        now = self._clock()
        utc = now.astimezone(UTC) if now.tzinfo else None
        candidates: dict[str, Any] = {"env.now": now if utc else None}
        if utc:
            candidates["env.hour_utc"] = utc.hour
            candidates["env.weekday"] = utc.weekday()
        request = ctx.request
        if request is not None:
            candidates["env.method"] = request.method
            candidates["env.path"] = request.url.path
            if "env.ip" in needed:
                candidates["env.ip"] = self._client_ip(request)
            for path in needed:
                if path.startswith("env.header."):
                    name = _norm_header(path[len("env.header.") :])
                    candidates[path] = self._header(request, name)
        for path in needed:
            value = candidates.get(path)
            if value is not None:
                found[path] = value
        return found


class AttributeResolver:
    """Calls each provider once, in order, for the paths it owns."""

    def __init__(self, providers: Sequence[AttributeProvider]) -> None:
        """
        Raises:
            ConfigurationError: Two providers claim overlapping paths.
        """
        self._providers = tuple(providers)
        seen: list[tuple[str, int]] = []
        for index, provider in enumerate(self._providers):
            for prefix in provider.prefixes:
                for other, other_index in seen:
                    if other_index != index and _overlap(prefix, other):
                        raise ConfigurationError(
                            f"attribute providers overlap on {prefix!r} / {other!r}"
                        )
                seen.append((prefix, index))

    @classmethod
    def default(
        cls,
        *,
        attributes: AttributeStore | None = None,
        claims_allowlist: Mapping[str, str] | Sequence[str] = (),
        headers_allowlist: Iterable[str] = (),
        trusted_proxies: Iterable[str] = (),
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        extra: Sequence[AttributeProvider] = (),
    ) -> AttributeResolver:
        """The standard set: context, subject, resource and environment."""
        return cls(
            [
                ContextAttributeProvider(claims_allowlist),
                SubjectAttributeProvider(attributes),
                ResourceAttributeProvider(attributes),
                EnvironmentProvider(
                    clock=clock,
                    headers_allowlist=headers_allowlist,
                    trusted_proxies=trusted_proxies,
                ),
                *extra,
            ]
        )

    async def resolve(
        self, ctx: AttributeRequest, needed: Iterable[str]
    ) -> dict[str, Any]:
        """Return ``path -> value`` for the needed paths (absent ones are omitted).

        Raises:
            ResourceNotFoundError: The resource loader said it does not exist.
            StoreUnavailableError: A provider failed.
        """
        wanted = frozenset(needed)
        values: dict[str, Any] = {}
        for provider in self._providers:
            mine = frozenset(
                p for p in wanted if any(_handles(x, p) for x in provider.prefixes)
            )
            if not mine:
                continue
            try:
                answer = await provider.load(ctx, mine)
            except AuthzError:
                raise
            except Exception as exc:
                logger.opt(exception=True).error("attribute provider failed")
                raise StoreUnavailableError("attribute provider failed") from exc
            for path, value in answer.items():
                if path in mine:
                    values[path] = value
        return values
