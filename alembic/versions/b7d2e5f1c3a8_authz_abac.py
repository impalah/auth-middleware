"""ABAC policy and attribute tables (auth_middleware.authz.abac)

Revision ID: b7d2e5f1c3a8
Revises: a3f1c9d2b7e4
Create Date: 2026-11-20 12:00:00.000000

Additive: two new tables; the assignment table is untouched.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b7d2e5f1c3a8"
down_revision: str | None = "a3f1c9d2b7e4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

POLICY = "authz_policy"
ATTRIBUTE = "authz_attribute"


def _ident(length: int) -> sa.types.TypeEngine:
    # Exact (case/accent sensitive) comparison on MySQL too (its default is not).
    return sa.String(length).with_variant(
        sa.String(length, collation="utf8mb4_bin"), "mysql", "mariadb"
    )


def _json() -> sa.types.TypeEngine:
    return sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        POLICY,
        sa.Column("id", _ident(100), nullable=False),
        sa.Column("effect", sa.String(length=10), nullable=False),
        sa.Column("scope_kind", _ident(50), nullable=False),
        sa.Column("scope_id", _ident(200), nullable=True),
        sa.Column("permissions", _json(), nullable=False),
        sa.Column("condition_doc", _json(), nullable=False),
        sa.Column("description", sa.String(length=500), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("hide", sa.Boolean(), nullable=False),
        sa.Column("enforce", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=10), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "effect IN ('deny', 'require', 'permit')", name=f"ck_{POLICY}_effect"
        ),
        sa.CheckConstraint(
            "status IN ('active', 'disabled')", name=f"ck_{POLICY}_status"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(f"ix_{POLICY}_scope", POLICY, ["scope_kind", "scope_id", "status"])
    op.create_table(
        ATTRIBUTE,
        sa.Column("id", sa.String(length=27), nullable=False),
        sa.Column("namespace", sa.String(length=10), nullable=False),
        sa.Column("kind", _ident(50), nullable=False),
        sa.Column("entity_id", _ident(500), nullable=False),
        sa.Column("attributes", _json(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "namespace IN ('principal', 'resource')", name=f"ck_{ATTRIBUTE}_namespace"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "namespace", "kind", "entity_id", name=f"uq_{ATTRIBUTE}_entity"
        ),
    )


def downgrade() -> None:
    op.drop_table(ATTRIBUTE)
    op.drop_index(f"ix_{POLICY}_scope", table_name=POLICY)
    op.drop_table(POLICY)
