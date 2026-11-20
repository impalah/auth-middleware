#!/usr/bin/env python

import asyncio
from typing import TYPE_CHECKING, Any

import click

try:  # the SQL providers live behind the optional "sqlalchemy" extra
    from auth_middleware.providers.sqlalchemy.sql_permissions_provider import (
        SqlPermissionsProvider,
    )
except ImportError:  # pragma: no cover - exercised by a subprocess test
    SqlPermissionsProvider = None  # type: ignore[assignment,misc]

if TYPE_CHECKING:
    from auth_middleware.authz import ScopeRef


@click.group()
def cli() -> None:
    """CLI for managing groups and permissions"""


@click.command()
@click.argument("username")
def get_permissions(username: str) -> None:
    """Get permissions for a user"""

    if SqlPermissionsProvider is None:
        raise click.ClickException(
            "get-permissions needs SQLAlchemy: "
            "pip install 'auth-middleware[sqlalchemy]'"
        )

    provider_cls = SqlPermissionsProvider

    async def _get_permissions() -> None:
        provider = provider_cls()
        permissions = await provider.get_permissions_from_db(username=username)
        click.echo(f"Permissions for {username}: {permissions}")

    asyncio.run(_get_permissions())


# cli.add_command(get_permissions)
cli.add_command(get_permissions)


# ---------------------------------------------------------------------------
# Scoped permissions (auth_middleware.authz)
# ---------------------------------------------------------------------------


def _parse_scope(value: str) -> "ScopeRef":
    from auth_middleware.authz import ScopeRef

    kind, sep, ident = value.partition(":")
    if not sep:
        raise click.BadParameter(
            "expected KIND:ID, e.g. studio:123", param_hint="scope"
        )
    try:
        return ScopeRef(kind, ident)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="scope") from exc


def _build_store(store: str) -> tuple[Any, Any]:
    """Build ``(store, aclose)`` from the environment (CLI only; library reads none)."""
    import os

    if store == "sqlalchemy":
        try:
            from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

            from auth_middleware.authz.stores import SqlAssignmentStore
        except ImportError as exc:
            raise click.ClickException(
                "the sqlalchemy store needs: pip install 'auth-middleware[sqlalchemy]'"
            ) from exc

        url = os.environ.get("AUTHZ_SQLALCHEMY_DATABASE_URI")
        if not url:
            raise click.UsageError("AUTHZ_SQLALCHEMY_DATABASE_URI is not set")
        engine = create_async_engine(url)
        return (
            SqlAssignmentStore(async_sessionmaker(engine, expire_on_commit=False)),
            engine.dispose,
        )
    try:
        from auth_middleware.authz.stores import DynamoDbAssignmentStore
    except ImportError as exc:
        raise click.ClickException(
            "the dynamodb store needs: pip install 'auth-middleware[dynamodb]'"
        ) from exc

    table = os.environ.get("AUTHZ_DYNAMODB_TABLE")
    if not table:
        raise click.UsageError("AUTHZ_DYNAMODB_TABLE is not set")
    dynamo = DynamoDbAssignmentStore(
        table_name=table, endpoint_url=os.environ.get("AUTHZ_DYNAMODB_ENDPOINT")
    )
    return dynamo, dynamo.aclose


def _run_on_store(
    store: str, catalog_path: str | None, fn: Any, *, raw: bool = False
) -> Any:
    """Build the backend inside the event loop, run ``fn(target)``, always dispose."""

    async def main() -> Any:
        backend, close = _build_store(store)
        try:
            target = backend if raw else _service_or_store(backend, catalog_path)
            return await fn(target)
        finally:
            await close()

    return asyncio.run(main())


def _line(a: Any) -> str:
    return (
        f"{a.scope.kind}:{a.scope.id} {a.principal_id} {a.role} "
        f"{a.status.value} r{a.revision}"
    )


def _authz_options(f: Any) -> Any:
    f = click.option(
        "--catalog",
        "catalog_path",
        type=click.Path(exists=True, dir_okay=False),
        default=None,
        help="Optional catalog (TOML/JSON): validates roles before writing.",
    )(f)
    return click.option(
        "--store",
        type=click.Choice(["sqlalchemy", "dynamodb"]),
        required=True,
        help="Backend; configured through AUTHZ_SQLALCHEMY_DATABASE_URI or "
        "AUTHZ_DYNAMODB_TABLE.",
    )(f)


@click.group()
def authz() -> None:
    """Manage scoped role assignments."""


def _service_or_store(store: Any, catalog_path: str | None) -> Any:
    if catalog_path is None:
        return store
    from pathlib import Path

    from auth_middleware.authz import AssignmentService, PermissionCatalog

    return AssignmentService(store, PermissionCatalog.from_file(Path(catalog_path)))


@authz.command("assign")
@_authz_options
@click.option("--principal", required=True, help="Principal id (the token sub).")
@click.option("--scope", required=True, help="KIND:ID, e.g. studio:123.")
@click.option("--role", required=True)
@click.option(
    "--no-validate",
    is_flag=True,
    help="Write the role without checking it against a catalog (a typo makes the "
    "principal's requests fail).",
)
def authz_assign(
    store: str,
    catalog_path: str | None,
    principal: str,
    scope: str,
    role: str,
    no_validate: bool,
) -> None:
    """Assign ROLE to a principal in a scope (validated against --catalog)."""
    from auth_middleware.authz import AuthzError, NewAssignment

    if catalog_path is None and not no_validate:
        raise click.UsageError(
            "give --catalog FILE to validate the role, or --no-validate to skip it"
        )
    ref = _parse_scope(scope)

    async def run(target: Any) -> Any:
        if hasattr(target, "members"):
            return await target.assign(principal, ref, role)
        return await target.assign(NewAssignment(principal, ref, role))

    try:
        click.echo(_line(_run_on_store(store, catalog_path, run)))
    except (AuthzError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


@authz.command("revoke")
@_authz_options
@click.option("--principal", required=True)
@click.option("--scope", required=True)
@click.option("--expected-revision", type=int, required=True)
def authz_revoke(
    store: str,
    catalog_path: str | None,
    principal: str,
    scope: str,
    expected_revision: int,
) -> None:
    """Revoke a principal's assignment (needs its current revision)."""
    from auth_middleware.authz import AuthzError

    ref = _parse_scope(scope)

    async def run(target: Any) -> Any:
        return await target.revoke(principal, ref, expected_revision=expected_revision)

    try:
        click.echo(_line(_run_on_store(store, catalog_path, run)))
    except (AuthzError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


@authz.command("list")
@_authz_options
@click.option("--principal", default=None, help="List this principal's scopes.")
@click.option("--scope", default=None, help="List this scope's principals.")
def authz_list(
    store: str, catalog_path: str | None, principal: str | None, scope: str | None
) -> None:
    """List assignments by principal or by scope."""
    if (principal is None) == (scope is None):
        raise click.UsageError("give exactly one of --principal / --scope")

    async def run(backend: Any) -> Any:
        if principal is not None:
            return await backend.list_assignments(principal)
        return await backend.list_for_scope(_parse_scope(scope or ""))

    for item in _run_on_store(store, catalog_path, run, raw=True):
        click.echo(_line(item))


# ---------------------------------------------------------------------------
# ABAC policies (auth_middleware.authz.abac)
# ---------------------------------------------------------------------------


@authz.group("policy")
def policy() -> None:
    """Manage ABAC policies (attribute conditions refining the roles)."""


def _policy_backend(store: str) -> tuple[Any, Any]:
    """Build ``(policy_store, aclose)`` from the environment (CLI only)."""
    import os

    if store == "sqlalchemy":
        try:
            from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

            from auth_middleware.authz.stores import SqlPolicyStore
        except ImportError as exc:
            raise click.ClickException(
                "the sqlalchemy store needs: pip install 'auth-middleware[sqlalchemy]'"
            ) from exc

        url = os.environ.get("AUTHZ_SQLALCHEMY_DATABASE_URI")
        if not url:
            raise click.UsageError("AUTHZ_SQLALCHEMY_DATABASE_URI is not set")
        engine = create_async_engine(url)
        return (
            SqlPolicyStore(async_sessionmaker(engine, expire_on_commit=False)),
            engine.dispose,
        )
    try:
        from auth_middleware.authz.stores import DynamoDbPolicyStore
    except ImportError as exc:
        raise click.ClickException(
            "the dynamodb store needs: pip install 'auth-middleware[dynamodb]'"
        ) from exc

    table = os.environ.get("AUTHZ_POLICY_TABLE")
    if not table:
        raise click.UsageError("AUTHZ_POLICY_TABLE is not set")
    dynamo = DynamoDbPolicyStore(
        table_name=table, endpoint_url=os.environ.get("AUTHZ_DYNAMODB_ENDPOINT")
    )
    return dynamo, dynamo.aclose


def _run_policy(store: str, fn: Any) -> Any:
    async def main() -> Any:
        backend, close = _policy_backend(store)
        try:
            return await fn(backend)
        finally:
            await close()

    try:
        return asyncio.run(main())
    except click.ClickException:
        raise
    except Exception as exc:
        from auth_middleware.authz import AuthzError

        if isinstance(exc, (AuthzError, ValueError)):
            raise click.ClickException(str(exc)) from exc
        raise


def _load_catalog(path: str) -> Any:
    from pathlib import Path

    from auth_middleware.authz import CatalogError, PermissionCatalog

    try:
        return PermissionCatalog.from_file(Path(path))
    except CatalogError as exc:
        raise click.ClickException(str(exc)) from exc


def _read_document(path: str) -> Any:
    import json
    import tomllib
    from pathlib import Path

    file = Path(path)
    try:
        text = file.read_text(encoding="utf-8")
        if file.suffix == ".toml":
            return tomllib.loads(text)
        return json.loads(text)
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(f"cannot read {path}: {exc}") from exc


def _read_policy(path: str) -> Any:
    from auth_middleware.authz import AuthzError
    from auth_middleware.authz.abac.types import new_policy_from_dict

    try:
        return new_policy_from_dict(_read_document(path))
    except AuthzError as exc:
        raise click.ClickException(str(exc)) from exc


def _policy_line(p: Any) -> str:
    return (
        f"{p.id} {p.effect.value} {p.scope.kind}:{p.scope.id or '*'} "
        f"{p.status.value} r{p.revision}"
    )


def _policy_store_option(f: Any) -> Any:
    return click.option(
        "--store",
        type=click.Choice(["sqlalchemy", "dynamodb"]),
        required=True,
        help="Backend; configured through AUTHZ_SQLALCHEMY_DATABASE_URI or "
        "AUTHZ_POLICY_TABLE (+ AUTHZ_DYNAMODB_ENDPOINT).",
    )(f)


def _catalog_option(f: Any) -> Any:
    return click.option(
        "--catalog",
        "catalog_path",
        type=click.Path(exists=True, dir_okay=False),
        required=True,
        help="Catalog (TOML/JSON) the policy is validated against.",
    )(f)


@policy.command("add")
@_policy_store_option
@click.option(
    "--file", "file_path", type=click.Path(exists=True, dir_okay=False), required=True
)
@_catalog_option
@click.option(
    "--allow-permit", is_flag=True, help="Accept permit policies (grant mode)."
)
def policy_add(
    store: str, file_path: str, catalog_path: str, allow_permit: bool
) -> None:
    """Validate a policy file against the catalog and store it."""
    from auth_middleware.authz.abac.service import PolicyService

    new = _read_policy(file_path)
    catalog = _load_catalog(catalog_path)

    async def run(admin: Any) -> Any:
        return await PolicyService(admin, catalog, allow_permit=allow_permit).create(
            new
        )

    click.echo(_policy_line(_run_policy(store, run)))


@policy.command("replace")
@click.argument("policy_id")
@_policy_store_option
@click.option(
    "--file", "file_path", type=click.Path(exists=True, dir_okay=False), required=True
)
@_catalog_option
@click.option("--expected-revision", type=int, required=True)
@click.option(
    "--allow-permit", is_flag=True, help="Accept permit policies (grant mode)."
)
def policy_replace(
    policy_id: str,
    store: str,
    file_path: str,
    catalog_path: str,
    expected_revision: int,
    allow_permit: bool,
) -> None:
    """Replace the content of a policy (needs its current revision)."""
    from auth_middleware.authz.abac.service import PolicyService

    new = _read_policy(file_path)
    catalog = _load_catalog(catalog_path)

    async def run(admin: Any) -> Any:
        service = PolicyService(admin, catalog, allow_permit=allow_permit)
        return await service.replace(
            policy_id, new, expected_revision=expected_revision
        )

    click.echo(_policy_line(_run_policy(store, run)))


@policy.command("list")
@_policy_store_option
@click.option("--scope", default=None, help="Only policies that apply to KIND:ID.")
@click.option("--all", "include_disabled", is_flag=True, help="Include disabled ones.")
def policy_list(store: str, scope: str | None, include_disabled: bool) -> None:
    """List policies."""
    from auth_middleware.authz.abac.types import PolicyStatus

    ref = _parse_scope(scope) if scope else None

    async def run(backend: Any) -> Any:
        status = None if include_disabled else PolicyStatus.ACTIVE
        found = await backend.list_all(status)
        if ref is not None:
            found = [p for p in found if p.scope.matches(ref)]
        return found

    for item in _run_policy(store, run):
        click.echo(_policy_line(item))


@policy.command("show")
@click.argument("policy_id")
@_policy_store_option
def policy_show(policy_id: str, store: str) -> None:
    """Print a policy as JSON."""
    import json

    async def run(backend: Any) -> Any:
        return await backend.get(policy_id)

    found = _run_policy(store, run)
    if found is None:
        raise click.ClickException(f"no such policy: {policy_id}")
    click.echo(json.dumps(found.to_dict(), indent=2, sort_keys=True))


def _set_status(store: str, policy_id: str, revision: int, status: str) -> None:
    from auth_middleware.authz.abac.types import PolicyStatus

    async def run(admin: Any) -> Any:
        return await admin.set_status(
            policy_id, PolicyStatus(status), expected_revision=revision
        )

    click.echo(_policy_line(_run_policy(store, run)))


@policy.command("disable")
@click.argument("policy_id")
@_policy_store_option
@click.option("--expected-revision", type=int, required=True)
def policy_disable(policy_id: str, store: str, expected_revision: int) -> None:
    """Disable a policy (kept as history; it stops applying)."""
    _set_status(store, policy_id, expected_revision, "disabled")


@policy.command("enable")
@click.argument("policy_id")
@_policy_store_option
@click.option("--expected-revision", type=int, required=True)
def policy_enable(policy_id: str, store: str, expected_revision: int) -> None:
    """Enable a disabled policy."""
    _set_status(store, policy_id, expected_revision, "active")


@policy.command("validate")
@click.option(
    "--file", "file_path", type=click.Path(exists=True, dir_okay=False), required=True
)
@_catalog_option
@click.option(
    "--allow-permit", is_flag=True, help="Accept permit policies (grant mode)."
)
def policy_validate(file_path: str, catalog_path: str, allow_permit: bool) -> None:
    """Check a policy file against the catalog (offline; nothing is stored)."""
    from auth_middleware.authz import AuthzError
    from auth_middleware.authz.abac.validation import validate_policy

    new = _read_policy(file_path)
    try:
        validate_policy(new, _load_catalog(catalog_path), allow_permit=allow_permit)
    except AuthzError as exc:
        problems = getattr(exc, "problems", None) or (str(exc),)
        raise click.ClickException("\n".join(f"- {p}" for p in problems)) from exc
    click.echo(f"OK: {new.id}")


def _flatten(prefix: str, data: Any, out: dict[str, Any]) -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            _flatten(f"{prefix}.{key}" if prefix else str(key), value, out)
    else:
        out[prefix] = data


@policy.command("test")
@click.option(
    "--file", "file_path", type=click.Path(exists=True, dir_okay=False), required=True
)
@click.option(
    "--context",
    "context_path",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help='JSON: {"subject": {...}, "resource": {...}, "env": {...}, '
    '"permission": "design.write"}.',
)
@click.option(
    "--catalog",
    "catalog_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Also validate the policy against this catalog first.",
)
def policy_test(file_path: str, context_path: str, catalog_path: str | None) -> None:
    """Evaluate a policy against a JSON context, offline (no store needed)."""
    from auth_middleware.authz import AuthzError
    from auth_middleware.authz.abac.conditions import (
        Tri,
        condition_paths,
        evaluate,
        parse_condition,
    )
    from auth_middleware.authz.abac.types import Effect
    from auth_middleware.authz.abac.validation import validate_policy

    new = _read_policy(file_path)
    try:
        if catalog_path is not None:
            validate_policy(new, _load_catalog(catalog_path), allow_permit=True)
        cond = parse_condition(new.condition)
    except AuthzError as exc:
        raise click.ClickException(str(exc)) from exc
    document = _read_document(context_path)
    if not isinstance(document, dict):
        raise click.ClickException("the context must be a JSON object")
    values: dict[str, Any] = {}
    _flatten("", {k: v for k, v in document.items() if k != "permission"}, values)
    if "permission" in document:
        values["action.permission"] = document["permission"]
    result = evaluate(cond, values)
    absent = sorted(p for p in condition_paths(cond) if p not in values)
    click.echo(f"condition: {result.value.upper()}")
    if absent:
        click.echo(f"missing attributes: {', '.join(absent)}")
    denies = (new.effect is Effect.DENY and result is not Tri.FALSE) or (
        new.effect is Effect.REQUIRE and result is not Tri.TRUE
    )
    if new.effect is Effect.PERMIT:
        verdict = "would GRANT" if result is Tri.TRUE else "would not grant"
    else:
        verdict = "would DENY" if denies else "would not deny"
    reason = (
        " (indeterminate fails closed)"
        if denies and result is Tri.INDETERMINATE
        else ""
    )
    click.echo(f"effect {new.effect.value}: {verdict}{reason}")


cli.add_command(authz)

if __name__ == "__main__":
    cli()
