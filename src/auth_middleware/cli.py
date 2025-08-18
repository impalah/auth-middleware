#!/usr/bin/env python

import asyncio

import click

from auth_middleware.providers.authz.sql_permissions_provider import (
    SqlPermissionsProvider,
)


@click.group()
def cli() -> None:
    """CLI for managing groups and permissions"""
    pass


@click.command()
@click.argument("username")
def get_permissions(username: str) -> None:
    """Get permissions for a user"""

    async def _get_permissions() -> None:
        provider = SqlPermissionsProvider()
        permissions = await provider.get_permissions_from_db(username=username)
        click.echo(f"Permissions for {username}: {permissions}")

    asyncio.run(_get_permissions())


# cli.add_command(get_permissions)
cli.add_command(get_permissions)

if __name__ == "__main__":
    cli()
