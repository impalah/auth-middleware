#!/usr/bin/env python

import click
import asyncio
from auth_middleware.providers.authz.sql_permissions_provider import (
    SqlPermissionsProvider,
)


@click.group()
def cli():
    """CLI for managing groups and permissions"""
    pass


@click.command()
@click.argument("username")
def get_permissions(username):
    """Get permissions for a user"""

    async def _get_permissions():
        provider = SqlPermissionsProvider()
        permissions = await provider.get_permissions_from_db(username=username)
        click.echo(f"Permissions for {username}: {permissions}")

    asyncio.run(_get_permissions())


# cli.add_command(get_permissions)

if __name__ == "__main__":
    cli()
