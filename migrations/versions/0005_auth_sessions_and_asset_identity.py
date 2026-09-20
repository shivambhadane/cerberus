"""auth sessions and per-user asset identity

Adds the refresh-token table, and changes what makes an asset "the same asset": from one row per
(tenant, host, port, protocol) to one row per (owner, host, port, protocol), so two users who
both hold a given host:port never see or overwrite each other's row. Rows with no owner (written
before users existed) keep the old per-tenant identity through a second, partial index.

Downgrading restores the per-tenant constraint, which fails if two users by then hold the same
host:port in one tenant. That is correct: the data no longer fits the old model.

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-20 11:11:54.922894
"""

import sqlalchemy as sa
from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('auth_sessions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('family_id', sa.String(length=36), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('rotated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_hash')
    )
    with op.batch_alter_table('auth_sessions', schema=None) as batch_op:
        batch_op.create_index('ix_auth_sessions_family', ['family_id'], unique=False)
        batch_op.create_index('ix_auth_sessions_user', ['user_id'], unique=False)

    with op.batch_alter_table('assets', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('uq_asset_identity'), type_='unique')
        batch_op.create_index('uq_asset_identity_legacy', ['tenant_id', 'hostname', 'port', 'protocol'], unique=True, sqlite_where=sa.text('user_id IS NULL'), postgresql_where=sa.text('user_id IS NULL'))
        batch_op.create_index('uq_asset_identity_owned', ['user_id', 'hostname', 'port', 'protocol'], unique=True, sqlite_where=sa.text('user_id IS NOT NULL'), postgresql_where=sa.text('user_id IS NOT NULL'))



def downgrade() -> None:
    with op.batch_alter_table('assets', schema=None) as batch_op:
        batch_op.drop_index('uq_asset_identity_owned', sqlite_where=sa.text('user_id IS NOT NULL'), postgresql_where=sa.text('user_id IS NOT NULL'))
        batch_op.drop_index('uq_asset_identity_legacy', sqlite_where=sa.text('user_id IS NULL'), postgresql_where=sa.text('user_id IS NULL'))
        batch_op.create_unique_constraint(batch_op.f('uq_asset_identity'), ['tenant_id', 'hostname', 'port', 'protocol'])

    with op.batch_alter_table('auth_sessions', schema=None) as batch_op:
        batch_op.drop_index('ix_auth_sessions_user')
        batch_op.drop_index('ix_auth_sessions_family')

    op.drop_table('auth_sessions')
