#!/usr/bin/env python3
"""
Script to synchronize version across all project files.

This script reads the version from pyproject.toml and updates it in:
- src/auth_middleware/__init__.py (__version__)
- docs_source/conf.py (release and version)
- Any other files that need version synchronization
"""

import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:
    # Python < 3.11
    try:
        import tomli as tomllib
    except ImportError:
        print("Error: tomllib/tomli not available. Install with: pip install tomli")
        sys.exit(1)


def get_version_from_pyproject() -> str | None:
    """Read version from pyproject.toml"""
    pyproject_path = Path("pyproject.toml")

    if not pyproject_path.exists():
        print(f"Error: {pyproject_path} not found")
        return None

    try:
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)

        version = data.get("project", {}).get("version")
        if not version:
            print("Error: version not found in pyproject.toml")
            return None

        print(f"📦 Found version in pyproject.toml: {version}")
        return version

    except Exception as e:
        print(f"Error reading pyproject.toml: {e}")
        return None


def update_init_version(version: str) -> bool:
    """Update __version__ in src/auth_middleware/__init__.py"""
    init_path = Path("src/auth_middleware/__init__.py")

    if not init_path.exists():
        print(f"Warning: {init_path} not found")
        return False

    try:
        content = init_path.read_text(encoding='utf-8')

        # Pattern to match __version__ = "x.y.z"
        pattern = r'__version__\s*=\s*["\']([^"\']+)["\']'
        new_content = re.sub(pattern, f'__version__ = "{version}"', content)

        if content != new_content:
            init_path.write_text(new_content, encoding='utf-8')
            print(f"✅ Updated __version__ in {init_path}")
            return True
        else:
            print(f"ℹ️  No changes needed in {init_path}")
            return True

    except Exception as e:
        print(f"Error updating {init_path}: {e}")
        return False


def update_sphinx_conf(version: str) -> bool:
    """Update version and release in docs_source/conf.py"""
    conf_path = Path("docs_source/conf.py")

    if not conf_path.exists():
        print(f"Warning: {conf_path} not found")
        return False

    try:
        content = conf_path.read_text(encoding='utf-8')
        original_content = content

        # Update release = 'x.y.z'
        release_pattern = r"release\s*=\s*['\"]([^'\"]+)['\"]"
        content = re.sub(release_pattern, f"release = '{version}'", content)

        # Update version = 'x.y.z'
        version_pattern = r"version\s*=\s*['\"]([^'\"]+)['\"]"
        content = re.sub(version_pattern, f"version = '{version}'", content)

        if content != original_content:
            conf_path.write_text(content, encoding='utf-8')
            print(f"✅ Updated version and release in {conf_path}")
            return True
        else:
            print(f"ℹ️  No changes needed in {conf_path}")
            return True

    except Exception as e:
        print(f"Error updating {conf_path}: {e}")
        return False


def main():
    """Main function to update all version references"""
    print("🔄 Synchronizing version across project files...")

    # Get version from pyproject.toml
    version = get_version_from_pyproject()
    if not version:
        sys.exit(1)

    success = True

    # Update __init__.py
    if not update_init_version(version):
        success = False

    # Update Sphinx conf.py
    if not update_sphinx_conf(version):
        success = False

    if success:
        print(f"✅ Successfully synchronized version {version} across all files")
    else:
        print("❌ Some files could not be updated")
        sys.exit(1)


if __name__ == "__main__":
    main()
