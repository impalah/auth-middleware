from __future__ import annotations

import asyncio
import json

import pytest
from click.testing import CliRunner
from sqlalchemy.ext.asyncio import create_async_engine

from auth_middleware.authz.stores.sql_models import metadata
from auth_middleware.cli import cli


@pytest.fixture
def env(tmp_path, monkeypatch):
    url = f"sqlite+aiosqlite:///{tmp_path}/cli.db"

    async def create():
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        await engine.dispose()

    asyncio.run(create())
    monkeypatch.setenv("AUTHZ_SQLALCHEMY_DATABASE_URI", url)
    return tmp_path


def run(*args):
    return CliRunner().invoke(cli, ["authz", *args])


def test_assign_list_revoke(env):
    r = run(
        "assign",
        "--no-validate",
        "--store",
        "sqlalchemy",
        "--principal",
        "u1",
        "--scope",
        "studio:s1",
        "--role",
        "EDI",
    )
    assert r.exit_code == 0, r.output
    assert r.output.strip() == "studio:s1 u1 EDI active r0"
    r = run("list", "--store", "sqlalchemy", "--principal", "u1")
    assert r.output.strip() == "studio:s1 u1 EDI active r0"
    r = run("list", "--store", "sqlalchemy", "--scope", "studio:s1")
    assert "u1" in r.output
    r = run(
        "revoke",
        "--store",
        "sqlalchemy",
        "--principal",
        "u1",
        "--scope",
        "studio:s1",
        "--expected-revision",
        "0",
    )
    assert r.output.strip() == "studio:s1 u1 EDI revoked r1"
    r = run(
        "revoke",
        "--store",
        "sqlalchemy",
        "--principal",
        "u1",
        "--scope",
        "studio:s1",
        "--expected-revision",
        "0",
    )
    assert r.exit_code != 0 and "Error" in r.output


def test_catalog_option_validates_roles(env):
    cat = env / "c.json"
    cat.write_text(
        json.dumps(
            {
                "scopes": [{"name": "studio"}],
                "permissions": [{"name": "a.b", "scope": "studio"}],
                "roles": {"EDI": ["a.b"]},
            }
        )
    )
    base = [
        "--store",
        "sqlalchemy",
        "--catalog",
        str(cat),
        "--principal",
        "u1",
        "--scope",
        "studio:s1",
    ]
    bad = run("assign", *base, "--role", "NOPE")
    assert bad.exit_code != 0 and "unknown role" in bad.output
    ok = run("assign", *base, "--role", "EDI")
    assert ok.exit_code == 0, ok.output


def test_usage_errors(env, monkeypatch):
    assert run("list", "--store", "sqlalchemy").exit_code != 0
    assert (
        run(
            "assign",
            "--store",
            "sqlalchemy",
            "--principal",
            "u",
            "--scope",
            "bad",
            "--role",
            "R",
        ).exit_code
        != 0
    )
    monkeypatch.delenv("AUTHZ_SQLALCHEMY_DATABASE_URI")
    r = run("list", "--store", "sqlalchemy", "--principal", "u")
    assert r.exit_code != 0 and "AUTHZ_SQLALCHEMY_DATABASE_URI" in r.output
    monkeypatch.delenv("AUTHZ_DYNAMODB_TABLE", raising=False)
    r = run("list", "--store", "dynamodb", "--principal", "u")
    assert "AUTHZ_DYNAMODB_TABLE" in r.output


def test_legacy_command_still_registered():
    assert "get-permissions" in cli.commands


def test_cli_works_without_optional_extras():
    """The CLI imports and reports a clear error when an extra is missing."""
    import subprocess
    import sys

    code = (
        "import sys\n"
        "for m in ('sqlalchemy', 'pynamodb'): sys.modules[m] = None\n"
        "from click.testing import CliRunner\n"
        "from auth_middleware.cli import cli\n"
        "r = CliRunner().invoke(cli, ['authz', 'list', '--store', 'sqlalchemy', '--principal', 'u'],"
        " env={'AUTHZ_SQLALCHEMY_DATABASE_URI': 'x'})\n"
        'assert r.exit_code != 0 and "auth-middleware[sqlalchemy]" in r.output, r.output\n'
        "r = CliRunner().invoke(cli, ['get-permissions', 'u'])\n"
        'assert r.exit_code != 0 and "auth-middleware[sqlalchemy]" in r.output, r.output\n'
        "r = CliRunner().invoke(cli, ['authz', 'list', '--store', 'dynamodb', '--principal', 'u'])\n"
        'assert r.exit_code != 0 and "auth-middleware[dynamodb]" in r.output, r.output\n'
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_assign_requires_a_catalog_or_an_explicit_no_validate(env):
    r = run(
        "assign",
        "--store",
        "sqlalchemy",
        "--principal",
        "u",
        "--scope",
        "studio:s1",
        "--role",
        "TYPO",
    )
    assert r.exit_code != 0 and "--no-validate" in r.output
