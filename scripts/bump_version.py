#!/usr/bin/env python3
"""Bump the project version and synchronise it across the project.

Usage:
    python scripts/bump_version.py patch|minor|major [--dry-run]
    python scripts/bump_version.py --set 1.2.3 [--dry-run]

Unlike a blind search-and-replace of the old version string, only the
``version = "..."`` line of the ``[project]`` table of ``pyproject.toml`` is
rewritten: a dependency pin, a comment or a URL that happens to contain the same
number is never touched. Afterwards ``update_version.py`` copies the version into
``src/auth_middleware/__init__.py`` and ``pages_source/conf.py``.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

PYPROJECT = Path("pyproject.toml")
_SEMVER = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_PROJECT_HEADER = re.compile(r"^\[project\]\s*$", re.MULTILINE)
_NEXT_TABLE = re.compile(r"^\[", re.MULTILINE)
_VERSION_LINE = re.compile(
    r'^(version\s*=\s*)"([^"\n]*)"([ \t]*(?:#.*)?)$', re.MULTILINE
)


def next_version(current: str, part: str) -> str:
    """Return ``current`` bumped by ``part`` (``patch``, ``minor`` or ``major``)."""
    match = _SEMVER.fullmatch(current)
    if match is None:
        raise ValueError(f"not a plain MAJOR.MINOR.PATCH version: {current!r}")
    major, minor, patch = (int(g) for g in match.groups())
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"unknown part: {part!r} (patch, minor or major)")


def replace_project_version(text: str, new: str) -> str:
    """Rewrite only the ``version`` line of the ``[project]`` table.

    Raises:
        ValueError: There is no ``[project]`` table or no single ``version`` line in it.
    """
    header = _PROJECT_HEADER.search(text)
    if header is None:
        raise ValueError("no [project] table in pyproject.toml")
    start = header.end()
    following = _NEXT_TABLE.search(text, start)
    end = following.start() if following else len(text)
    section = text[start:end]
    found = _VERSION_LINE.findall(section)
    if len(found) != 1:
        raise ValueError(
            f"expected exactly one version line in [project], found {len(found)}"
        )
    updated = _VERSION_LINE.sub(
        lambda m: f'{m.group(1)}"{new}"{m.group(3)}', section, 1
    )
    return text[:start] + updated + text[end:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("part", nargs="?", choices=["patch", "minor", "major"])
    parser.add_argument(
        "--set", dest="explicit", help="set an explicit MAJOR.MINOR.PATCH"
    )
    parser.add_argument("--dry-run", action="store_true", help="show, do not write")
    args = parser.parse_args(argv)
    if (args.part is None) == (args.explicit is None):
        parser.error("give exactly one of patch|minor|major or --set VERSION")

    text = PYPROJECT.read_text(encoding="utf-8")
    current = tomllib.loads(text)["project"]["version"]
    new = args.explicit or next_version(current, args.part)
    if _SEMVER.fullmatch(new) is None:
        parser.error(f"not a plain MAJOR.MINOR.PATCH version: {new!r}")
    print(f"Current version: {current}")
    print(f"New version: {new}")
    if args.dry_run:
        return 0
    PYPROJECT.write_text(replace_project_version(text, new), encoding="utf-8")

    sys.path.insert(0, str(Path(__file__).parent))
    import update_version

    sys.argv = ["update_version.py"]
    update_version.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
