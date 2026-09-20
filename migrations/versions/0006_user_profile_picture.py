"""user profile picture and sign-in method

Adds `users.picture_url` and `users.auth_provider`, filled from the identity provider's verified
token (Google photo, and how the person signed in). Both nullable: existing accounts simply have
neither until their next sign-in.

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-20 16:20:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('picture_url', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('auth_provider', sa.String(length=32), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('auth_provider')
        batch_op.drop_column('picture_url')
