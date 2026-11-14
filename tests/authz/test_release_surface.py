from __future__ import annotations

import subprocess
import sys

import auth_middleware

# Public names of auth_middleware 0.6.2 that must still exist.
PUBLIC_0_6_2 = [
    "BasicAuthMiddleware",
    "JwtAuthMiddleware",
    "User",
    "require_user",
    "require_groups",
    "require_roles",
    "require_permissions",
    "get_current_user",
]


def test_no_public_name_of_0_6_2_disappeared():
    assert auth_middleware.__version__ == "0.7.0"
    for name in PUBLIC_0_6_2:
        assert hasattr(auth_middleware, name) or _importable(name), name


def _importable(name: str) -> bool:
    import importlib

    for mod in (
        "auth_middleware.guards.functions",
        "auth_middleware.types.user",
        "auth_middleware.jwt_auth_middleware",
        "auth_middleware.basic_auth_middleware",
    ):
        if hasattr(importlib.import_module(mod), name):
            return True
    return False


def test_authz_is_not_re_exported_from_the_top_level_package():
    assert "authz" not in getattr(auth_middleware, "__all__", [])


def test_import_authz_works_without_optional_dependencies():
    code = (
        "import sys; import auth_middleware.authz as a; "
        "heavy = {'sqlalchemy', 'pynamodb', 'boto3', 'aioboto3', 'botocore'}; "
        "bad = heavy & {m.split('.')[0] for m in sys.modules}; "
        "sys.exit(1 if bad else 0)"
    )
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0
