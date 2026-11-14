"""Scoped-permissions assignment table (auth_middleware.authz)

Revision ID: a3f1c9d2b7e4
Revises: de961fac6f27
Create Date: 2026-11-14 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "a3f1c9d2b7e4"
down_revision: str | None = "de961fac6f27"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "authz_assignment"


def _ident(length: int) -> sa.types.TypeEngine:
    # Exact (case/accent sensitive) comparison on MySQL too (its default is not).
    return sa.String(length).with_variant(
        sa.String(length, collation="utf8mb4_bin"), "mysql", "mariadb"
    )


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(length=27), nullable=False),
        sa.Column("principal_id", _ident(500), nullable=False),
        sa.Column("scope_kind", _ident(50), nullable=False),
        sa.Column("scope_id", _ident(200), nullable=False),
        sa.Column("role", _ident(100), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "attributes",
            sa.JSON().with_variant(postgresql.JSONB(), "postgresql"),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')", name=f"ck_{TABLE}_status"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "principal_id",
            "scope_kind",
            "scope_id",
            name=f"uq_{TABLE}_principal_scope",
        ),
    )
    op.create_index(f"ix_{TABLE}_scope", TABLE, ["scope_kind", "scope_id"])


def downgrade() -> None:
    op.drop_index(f"ix_{TABLE}_scope", table_name=TABLE)
    op.drop_table(TABLE)
