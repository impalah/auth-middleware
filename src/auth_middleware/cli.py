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


cli.add_command(authz)

if __name__ == "__main__":
    cli()
