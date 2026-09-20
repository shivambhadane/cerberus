"""allow multi-user testbeds and docker labs

Updates uq_domain_one_verified_owner index to exclude verification_method in ('testbed', 'lab'),
so public benchmark targets (e.g. testphp.vulnweb.com) and local testbeds (127.0.0.1) can be
independently verified and tested across multiple user accounts.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-20 19:40:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('domains', schema=None) as batch_op:
        batch_op.drop_index('uq_domain_one_verified_owner')
        batch_op.create_index(
            'uq_domain_one_verified_owner',
            ['domain'],
            unique=True,
            sqlite_where=sa.text("verification_status = 'verified' AND verification_method NOT IN ('testbed', 'lab')"),
            postgresql_where=sa.text("verification_status = 'verified' AND verification_method NOT IN ('testbed', 'lab')"),
        )


def downgrade() -> None:
    with op.batch_alter_table('domains', schema=None) as batch_op:
        batch_op.drop_index('uq_domain_one_verified_owner')
        batch_op.create_index(
            'uq_domain_one_verified_owner',
            ['domain'],
            unique=True,
            sqlite_where=sa.text("verification_status = 'verified'"),
            postgresql_where=sa.text("verification_status = 'verified'"),
        )
