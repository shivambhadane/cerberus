"""add real per-stage scan progress

Adds `scans.progress`, a JSON object the pipeline updates as each real stage of a scan
completes (asset discovery, DNS resolution, port/service discovery, HTTP discovery,
vulnerability scanning, enrichment, risk analysis), plus live counts (subdomains,
hosts resolved, open ports, technologies, findings). Default `{}` (a scan not yet
started, or one from before this column existed, has no progress to show — never a
fabricated one).

This is additive only: nothing reads `scans.status` any differently, and a stage not
reported here (a passive profile that never reaches vulnerability scanning, say) is
simply absent from `progress["completed"]`, not invented.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-02 15:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('progress', sa.JSON(), nullable=False, server_default=sa.text("'{}'"))
        )


def downgrade() -> None:
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('progress')
