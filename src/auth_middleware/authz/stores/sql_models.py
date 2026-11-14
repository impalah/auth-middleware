"""SQLAlchemy table of the assignment store (own metadata, not the legacy one)."""

from __future__ import annotations

import re
from typing import Any

try:
    from sqlalchemy import (
        JSON,
        CheckConstraint,
        Column,
        DateTime,
        Index,
        Integer,
        MetaData,
        String,
        Table,
        UniqueConstraint,
    )
    from sqlalchemy.dialects.postgresql import JSONB
except ImportError as exc:  # pragma: no cover - exercised without the extra
    raise ImportError(
        "the SQL assignment store needs SQLAlchemy: "
        "pip install 'auth-middleware[sqlalchemy]'"
    ) from exc

DEFAULT_TABLE_NAME = "authz_assignment"
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

#: Metadata applications can include in their own ``target_metadata``.
metadata = MetaData()


def _ident(length: int) -> Any:
    """Identifier column: exact (case/accent sensitive) comparison on every backend.

    MySQL's default collations are case- and accent-insensitive, which would make
    ``Abc`` and ``abc`` the same principal; ``utf8mb4_bin`` keeps them distinct.
    """
    return String(length).with_variant(
        String(length, collation="utf8mb4_bin"), "mysql", "mariadb"
    )


def build_table(meta: MetaData, name: str = DEFAULT_TABLE_NAME) -> Table:
    """Build the assignment table in ``meta`` under ``name``.

    Raises:
        ValueError: ``name`` is not a plain SQL identifier.
    """
    if not _IDENT_RE.fullmatch(name):
        raise ValueError(f"invalid table name: {name!r}")
    return Table(
        name,
        meta,
        Column("id", String(27), primary_key=True),
        Column("principal_id", _ident(500), nullable=False),
        Column("scope_kind", _ident(50), nullable=False),
        Column("scope_id", _ident(200), nullable=False),
        Column("role", _ident(100), nullable=False),
        Column("status", String(10), nullable=False),
        Column("revision", Integer, nullable=False, default=0),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
        Column("attributes", JSON().with_variant(JSONB(), "postgresql"), nullable=True),
        CheckConstraint("status IN ('active', 'revoked')", name=f"ck_{name}_status"),
        UniqueConstraint(
            "principal_id", "scope_kind", "scope_id", name=f"uq_{name}_principal_scope"
        ),
        Index(f"ix_{name}_scope", "scope_kind", "scope_id"),
    )


assignment_table = build_table(metadata)
