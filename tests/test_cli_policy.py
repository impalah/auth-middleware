"""AUTHZ-032: authcli authz policy ..."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys

import pytest
from click.testing import CliRunner
from sqlalchemy.ext.asyncio import create_async_engine

from auth_middleware.authz.stores.sql_models import metadata
from auth_middleware.cli import cli

CATALOG = {
    "scopes": [{"name": "studio"}],
    "permissions": [
        {"name": "design.read", "scope": "studio"},
        {"name": "design.write", "scope": "studio"},
    ],
    "roles": {"EDI": ["design.read", "design.write"]},
    "attributes": {
        "subject.assignment.tenant_status": {
            "type": "string",
            "enum": ["active", "suspended"],
        },
        "subject.attrs.clearance": {"type": "int"},
    },
}
POLICY = {
    "id": "suspended-readonly",
    "effect": "deny",
    "permissions": ["design.write"],
    "scope": {"kind": "studio"},
    "condition": {"eq": [{"attr": "subject.assignment.tenant_status"}, "suspended"]},
}


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
    (tmp_path / "catalog.json").write_text(json.dumps(CATALOG))
    (tmp_path / "policy.json").write_text(json.dumps(POLICY))
    return tmp_path


def run(*args):
    return CliRunner().invoke(cli, ["authz", "policy", *args])


def base(env):
    return (
        ["--store", "sqlalchemy"],
        str(env / "policy.json"),
        str(env / "catalog.json"),
    )


def test_add_list_show_disable_enable_replace(env):
    store, policy_file, catalog = base(env)
    r = run("add", *store, "--file", policy_file, "--catalog", catalog)
    assert r.exit_code == 0, r.output
    assert r.output.strip() == "suspended-readonly deny studio:* active r0"
    assert (
        run("list", *store).output.strip()
        == "suspended-readonly deny studio:* active r0"
    )
    assert (
        run("list", *store, "--scope", "studio:s1").output.strip().endswith("active r0")
    )
    assert run("list", *store, "--scope", "company:x").output.strip() == ""
    shown = json.loads(run("show", "suspended-readonly", *store).output)
    assert shown["effect"] == "deny" and shown["revision"] == 0

    r = run("disable", "suspended-readonly", *store, "--expected-revision", "0")
    assert r.output.strip().endswith("disabled r1")
    assert run("list", *store).output.strip() == ""
    assert "disabled" in run("list", *store, "--all").output
    r = run("enable", "suspended-readonly", *store, "--expected-revision", "1")
    assert r.output.strip().endswith("active r2")

    changed = dict(POLICY, description="v2")
    (env / "v2.json").write_text(json.dumps(changed))
    r = run(
        "replace",
        "suspended-readonly",
        *store,
        "--file",
        str(env / "v2.json"),
        "--catalog",
        catalog,
        "--expected-revision",
        "2",
    )
    assert r.exit_code == 0 and r.output.strip().endswith("r3"), r.output
    stale = run(
        "replace",
        "suspended-readonly",
        *store,
        "--file",
        str(env / "v2.json"),
        "--catalog",
        catalog,
        "--expected-revision",
        "0",
    )
    assert stale.exit_code == 1 and "stale" in stale.output


def test_add_rejects_invalid_and_duplicate(env):
    store, policy_file, catalog = base(env)
    bad = dict(
        POLICY,
        id="bad",
        condition={"eq": [{"attr": "subject.attrs.ghost"}, 1]},
        permissions=["nope.*"],
    )
    (env / "bad.json").write_text(json.dumps(bad))
    r = run("add", *store, "--file", str(env / "bad.json"), "--catalog", catalog)
    assert r.exit_code == 1 and "ghost" in r.output and "matches nothing" in r.output
    assert run("list", *store).output.strip() == ""
    assert (
        run("add", *store, "--file", policy_file, "--catalog", catalog).exit_code == 0
    )
    again = run("add", *store, "--file", policy_file, "--catalog", catalog)
    assert again.exit_code == 1 and "already exists" in again.output
    assert run("show", "ghost", *store).exit_code == 1


def test_permit_needs_the_flag(env):
    store, _, catalog = base(env)
    permit = dict(
        POLICY,
        id="grant",
        effect="permit",
        condition={"eq": [{"attr": "subject.id"}, "u1"]},
    )
    (env / "permit.json").write_text(json.dumps(permit))
    r = run("add", *store, "--file", str(env / "permit.json"), "--catalog", catalog)
    assert r.exit_code == 1 and "grant" in r.output
    ok = run(
        "add",
        *store,
        "--file",
        str(env / "permit.json"),
        "--catalog",
        catalog,
        "--allow-permit",
    )
    assert ok.exit_code == 0, ok.output


def test_validate_is_offline(env, monkeypatch):
    monkeypatch.delenv("AUTHZ_SQLALCHEMY_DATABASE_URI")
    _, policy_file, catalog = base(env)
    r = run("validate", "--file", policy_file, "--catalog", catalog)
    assert r.exit_code == 0 and r.output.strip() == "OK: suspended-readonly"
    (env / "bad.json").write_text(json.dumps(dict(POLICY, permissions=["zzz"])))
    bad = run("validate", "--file", str(env / "bad.json"), "--catalog", catalog)
    assert bad.exit_code == 1 and "matches nothing" in bad.output


@pytest.mark.parametrize(
    "context,expected,missing",
    [
        ({"subject": {"assignment": {"tenant_status": "suspended"}}}, "TRUE", False),
        ({"subject": {"assignment": {"tenant_status": "active"}}}, "FALSE", False),
        ({"subject": {"id": "u1"}}, "INDETERMINATE", True),
    ],
)
def test_policy_test_three_values(env, context, expected, missing):
    _, policy_file, _ = base(env)
    (env / "ctx.json").write_text(json.dumps(context))
    r = run("test", "--file", policy_file, "--context", str(env / "ctx.json"))
    assert r.exit_code == 0, r.output
    assert f"condition: {expected}" in r.output
    assert (
        "missing attributes: subject.assignment.tenant_status" in r.output
    ) is missing
    verdict = "would not deny" if expected == "FALSE" else "would DENY"
    assert verdict in r.output
    if expected == "INDETERMINATE":
        assert "fails closed" in r.output


def test_policy_test_permission_context_and_errors(env):
    _, policy_file, catalog = base(env)
    perm = dict(
        POLICY,
        effect="require",
        condition={"eq": [{"attr": "action.permission"}, "design.write"]},
    )
    (env / "perm.json").write_text(json.dumps(perm))
    (env / "ctx.json").write_text(json.dumps({"permission": "design.write"}))
    r = run(
        "test",
        "--file",
        str(env / "perm.json"),
        "--context",
        str(env / "ctx.json"),
        "--catalog",
        catalog,
    )
    assert "condition: TRUE" in r.output and "would not deny" in r.output
    (env / "list.json").write_text("[1]")
    assert (
        run(
            "test", "--file", policy_file, "--context", str(env / "list.json")
        ).exit_code
        == 1
    )
    (env / "garbage.json").write_text("{nope")
    assert (
        run(
            "test", "--file", policy_file, "--context", str(env / "garbage.json")
        ).exit_code
        == 1
    )
    (env / "badcond.json").write_text(json.dumps(dict(POLICY, condition={"zz": 1})))
    assert (
        run(
            "test",
            "--file",
            str(env / "badcond.json"),
            "--context",
            str(env / "ctx.json"),
        ).exit_code
        == 1
    )


def test_permit_verdicts(env):
    permit = dict(
        POLICY,
        id="grant",
        effect="permit",
        condition={"eq": [{"attr": "subject.id"}, "u1"]},
    )
    (env / "permit.json").write_text(json.dumps(permit))
    (env / "yes.json").write_text(json.dumps({"subject": {"id": "u1"}}))
    (env / "no.json").write_text(json.dumps({"subject": {"id": "u2"}}))
    assert (
        "would GRANT"
        in run(
            "test",
            "--file",
            str(env / "permit.json"),
            "--context",
            str(env / "yes.json"),
        ).output
    )
    assert (
        "would not grant"
        in run(
            "test",
            "--file",
            str(env / "permit.json"),
            "--context",
            str(env / "no.json"),
        ).output
    )


def test_missing_configuration(env, monkeypatch):
    store, policy_file, catalog = base(env)
    monkeypatch.delenv("AUTHZ_SQLALCHEMY_DATABASE_URI")
    r = run("list", *store)
    assert r.exit_code == 2 and "AUTHZ_SQLALCHEMY_DATABASE_URI" in r.output
    monkeypatch.delenv("AUTHZ_POLICY_TABLE", raising=False)
    r = run("list", "--store", "dynamodb")
    assert r.exit_code == 2 and "AUTHZ_POLICY_TABLE" in r.output


def test_toml_policy_file(env):
    store, _, catalog = base(env)
    (env / "p.toml").write_text(
        'id = "t1"\neffect = "require"\npermissions = ["design.read"]\n'
        'scope = {kind = "studio", id = "s1"}\n'
        'condition = {gte = [{attr = "subject.attrs.clearance"}, 2]}\n'
    )
    r = run("add", *store, "--file", str(env / "p.toml"), "--catalog", catalog)
    assert r.exit_code == 0 and "studio:s1" in r.output, r.output


def test_policy_cli_imports_without_sqlalchemy():
    code = (
        "import sys\n"
        "sys.modules['sqlalchemy'] = None\n"
        "from click.testing import CliRunner\n"
        "from auth_middleware.cli import cli\n"
        "args = ['authz', 'policy', 'list', '--store', 'sqlalchemy']\n"
        "env = {'AUTHZ_SQLALCHEMY_DATABASE_URI': 'x'}\n"
        "r = CliRunner().invoke(cli, args, env=env)\n"
        "print(r.exit_code, 'sqlalchemy' in r.output)\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.split() == ["1", "True"]
