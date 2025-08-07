# Version Synchronization Script

This directory contains utilities for managing version consistency across the Cache Middleware project.

## `update_version.py`

This script automatically synchronizes the version number across all project files after a version bump.

### What it does

1. **Reads version** from `pyproject.toml` (the authoritative source)
2. **Updates** `src/auth_middleware/__init__.py` with the new `__version__`
3. **Updates** `docs_source/conf.py` with the new `release = version = 'x.y.z'`
4. **Reports** all changes made

### Usage

The script is automatically executed when you run:

```bash
# Local development - bumps version and syncs all files
make bump-version           # Bumps patch version and syncs all files
make bump-version PART=minor # Bumps minor version and syncs all files

# Manual sync only (without version bump)
make sync-version           # Syncs current version from pyproject.toml

# Direct script execution
uv run python scripts/update_version.py
```

### Integration

- **Makefile**:
  - `bump-version` target runs `bump2version` then executes this script
  - `sync-version` target runs only this script for manual sync
- **GitHub Actions**: Runs during the release workflow after version bump
- **Files managed**:
  - `pyproject.toml` (source of truth, updated by bump2version)
  - `src/auth_middleware/__init__.py` (`__version__` variable)
  - `docs_source/conf.py` (`release = version = 'x.y.z'` line)

### Example Output

```
🔄 Synchronizing version across project files...
📦 Found version in pyproject.toml: 0.1.5
✅ Updated __version__ in src/auth_middleware/__init__.py
✅ Updated version and release in docs_source/conf.py
✅ Successfully synchronized version 0.1.5 across all files
```

### Error Handling

The script will exit with code 1 if:

- `pyproject.toml` is not found or doesn't contain a version
- Any target file cannot be read or written
- Version patterns are not found in target files

### Backup Configuration

A `.bumpversion.cfg` file is included for future reference, but the current implementation uses:

1. `bump2version` to update `pyproject.toml` only
2. This Python script to sync all other files

This approach provides maximum reliability and easy debugging.

### Dependencies

- Python 3.11+ (uses built-in `tomllib`)
- Python 3.10 and below: requires `tomli` package (included in project dependencies)
