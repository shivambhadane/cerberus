"""add an admin flag to users

Adds `users.is_admin`, boolean, default false. Grants read-only cross-tenant visibility
(api/admin.py) to the account it is set on; it grants no scanning power beyond what any
verified-domain owner already has. Purely additive: every existing account defaults to
`is_admin = false`, unchanged behaviour until an operator sets it by hand
(scripts/grant_admin.py) — there is no API that sets it.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-02 12:00:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('is_admin', sa.Boolean(), nullable=False, server_default=sa.false())
        )


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('is_admin')
