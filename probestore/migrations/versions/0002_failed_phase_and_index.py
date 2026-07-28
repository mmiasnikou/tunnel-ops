"""add probe_result.failed_phase and the (node_id, ts) lookup index

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-28

Rationale: querying "latest per node" and "history since X" both filter on
node_id and order by ts. Without this index those become sequential scans as
soon as history grows past a few thousand rows.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "probe_result", sa.Column("failed_phase", sa.String(length=16), nullable=True)
    )
    op.create_index(
        "ix_probe_result_node_ts", "probe_result", ["node_id", "ts"], unique=False
    )
    # Backfill: rows written before this column existed can still be classified.
    op.execute(
        """
        UPDATE probe_result
           SET failed_phase = CASE
               WHEN tcp_ok IS FALSE THEN 'tcp'
               WHEN tls_ok IS FALSE THEN 'tls'
               ELSE NULL
           END
        """
    )


def downgrade() -> None:
    op.drop_index("ix_probe_result_node_ts", table_name="probe_result")
    op.drop_column("probe_result", "failed_phase")
