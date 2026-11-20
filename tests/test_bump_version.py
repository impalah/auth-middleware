"""The version bump touches only the [project] version line."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location(
    "bump_version", ROOT / "scripts/bump_version.py"
)
bump = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bump)  # type: ignore[union-attr]

PYPROJECT = """\
[project]
name = "x"
version = "0.7.0"  # keep in sync
description = "mentions 0.7.0 on purpose"
dependencies = [
    "svix-ksuid>=0.7.0",
]

[tool.ruff]
# Added by the 0.7.0 quality review
version = "0.7.0"
"""


def test_only_the_project_version_line_changes():
    out = bump.replace_project_version(PYPROJECT, "0.7.1")
    assert 'version = "0.7.1"  # keep in sync' in out
    assert "svix-ksuid>=0.7.0" in out
    assert "mentions 0.7.0 on purpose" in out
    assert "Added by the 0.7.0 quality review" in out
    assert out.count('version = "0.7.0"') == 1  # the [tool.ruff] one is untouched
    assert out.replace("0.7.1", "0.7.0") == PYPROJECT


@pytest.mark.parametrize(
    "current,part,expected",
    [
        ("0.7.1", "patch", "0.7.2"),
        ("0.7.1", "minor", "0.8.0"),
        ("0.7.1", "major", "1.0.0"),
        ("1.9.9", "patch", "1.9.10"),
    ],
)
def test_next_version(current, part, expected):
    assert bump.next_version(current, part) == expected


def test_rejects_bad_input():
    with pytest.raises(ValueError):
        bump.next_version("1.0", "patch")
    with pytest.raises(ValueError):
        bump.next_version("1.0.0", "huge")
    with pytest.raises(ValueError):
        bump.replace_project_version("[tool.x]\nversion = '1'\n", "1.0.0")
    with pytest.raises(ValueError):
        bump.replace_project_version('[project]\nname = "x"\n', "1.0.0")
    with pytest.raises(ValueError):
        bump.replace_project_version(
            '[project]\nversion = "1.0.0"\nversion = "1.0.1"\n', "1.0.2"
        )


def test_end_to_end_in_a_copy(tmp_path):
    (tmp_path / "scripts").mkdir()
    for name in ("bump_version.py", "update_version.py"):
        shutil.copy(ROOT / "scripts" / name, tmp_path / "scripts" / name)
    (tmp_path / "pyproject.toml").write_text(PYPROJECT)
    (tmp_path / "src/auth_middleware").mkdir(parents=True)
    (tmp_path / "src/auth_middleware/__init__.py").write_text('__version__ = "0.7.0"\n')
    (tmp_path / "pages_source").mkdir()
    (tmp_path / "pages_source/conf.py").write_text("release = version = '0.7.0'\n")

    def run(*args):
        return subprocess.run(
            [sys.executable, "scripts/bump_version.py", *args],
            cwd=tmp_path,
            capture_output=True,
            text=True,
        )

    dry = run("minor", "--dry-run")
    assert dry.returncode == 0 and "New version: 0.8.0" in dry.stdout
    assert (tmp_path / "pyproject.toml").read_text() == PYPROJECT
    done = run("minor")
    assert done.returncode == 0, done.stderr
    text = (tmp_path / "pyproject.toml").read_text()
    assert 'version = "0.8.0"' in text and "svix-ksuid>=0.7.0" in text
    assert "0.8.0" in (tmp_path / "src/auth_middleware/__init__.py").read_text()
    assert "0.8.0" in (tmp_path / "pages_source/conf.py").read_text()
    assert run("--set", "2.0.0").returncode == 0
    assert run("--set", "nope").returncode != 0
    assert run().returncode != 0
