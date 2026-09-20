"""users and domains

Adds the ownership layer: users, the domains they claim, and nullable ownership columns on
scans and assets. Purely additive. `tenant_id` stays where it is, and rows written before users
existed keep NULL ownership rather than having a user invented for them.

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-20 10:58:22.659261
"""

import sqlalchemy as sa
from alembic import op

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), server_default='', nullable=False),
        # sa.false()/sa.true() render correctly per dialect; a literal 0/1 is rejected by PostgreSQL.
        sa.Column('email_verified', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )
    op.create_table(
        'domains',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('verification_token', sa.String(length=64), nullable=False),
        sa.Column('verification_method', sa.String(length=16), server_default='dns_txt', nullable=False),
        sa.Column('verification_status', sa.String(length=16), server_default='pending', nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'domain', name='uq_domain_per_user'),
    )
    with op.batch_alter_table('domains', schema=None) as batch_op:
        batch_op.create_index('ix_domains_user', ['user_id'], unique=False)
        # Claims are not unique, proof is: one verified owner per domain.
        batch_op.create_index(
            'uq_domain_one_verified_owner',
            ['domain'],
            unique=True,
            sqlite_where=sa.text("verification_status = 'verified'"),
            postgresql_where=sa.text("verification_status = 'verified'"),
        )

    for table in ('assets', 'scans'):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.add_column(sa.Column('user_id', sa.String(length=36), nullable=True))
            batch_op.add_column(sa.Column('domain_id', sa.String(length=36), nullable=True))
            batch_op.create_index(f'ix_{table}_user', ['user_id'], unique=False)
            batch_op.create_index(f'ix_{table}_domain', ['domain_id'], unique=False)
            # Named, so the downgrade can find them (an unnamed constraint cannot be dropped).
            batch_op.create_foreign_key(f'fk_{table}_user_id', 'users', ['user_id'], ['id'])
            batch_op.create_foreign_key(f'fk_{table}_domain_id', 'domains', ['domain_id'], ['id'])


def downgrade() -> None:
    for table in ('scans', 'assets'):
        with op.batch_alter_table(table, schema=None) as batch_op:
            batch_op.drop_constraint(f'fk_{table}_domain_id', type_='foreignkey')
            batch_op.drop_constraint(f'fk_{table}_user_id', type_='foreignkey')
            batch_op.drop_index(f'ix_{table}_domain')
            batch_op.drop_index(f'ix_{table}_user')
            batch_op.drop_column('domain_id')
            batch_op.drop_column('user_id')

    with op.batch_alter_table('domains', schema=None) as batch_op:
        batch_op.drop_index('uq_domain_one_verified_owner')
        batch_op.drop_index('ix_domains_user')

    op.drop_table('domains')
    op.drop_table('users')
