"""initial schema: node, probe_run, probe_result

Revision ID: 0001
Revises:
Create Date: 2026-07-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("addr", sa.String(length=255), nullable=False),
        sa.Column("sni", sa.String(length=255), nullable=False),
        sa.Column("provider", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("addr", "sni", name="uq_node_addr_sni"),
    )

    op.create_table(
        "probe_run",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("external_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("external_id", name="uq_probe_run_external_id"),
    )

    op.create_table(
        "probe_result",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "node_id",
            sa.Integer(),
            sa.ForeignKey("node.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "run_id",
            sa.Integer(),
            sa.ForeignKey("probe_run.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tcp_ok", sa.Boolean(), nullable=False),
        sa.Column("tls_ok", sa.Boolean(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("probe_result")
    op.drop_table("probe_run")
    op.drop_table("node")
