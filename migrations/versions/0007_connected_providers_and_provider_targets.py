"""connected providers and provider-verified targets

Adds what deployment-platform verification (Vercel, Netlify, Cloudflare Pages) needs, and nothing that
touches the scanner:

  * connected_providers: a user's connection to a platform account. Its tokens are stored encrypted.
  * oauth_states: an in-flight OAuth authorisation. Single-use, short-lived, bound to a user and a
    browser. Only hashes are stored.
  * domains.provider / provider_connection_id / provider_project_id / provider_resource_id: how a
    platform-verified target was proven. All nullable, so every existing (DNS-verified) domain is
    untouched.

Purely additive. Existing rows keep working with no change.

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-20 17:05:00.000000
"""

import sqlalchemy as sa
from alembic import op

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'connected_providers',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('provider', sa.String(length=16), nullable=False),
        sa.Column('provider_account_id', sa.String(length=128), nullable=False),
        sa.Column('account_label', sa.String(length=255), server_default='', nullable=False),
        sa.Column('access_token_encrypted', sa.Text(), nullable=False),
        sa.Column('refresh_token_encrypted', sa.Text(), nullable=True),
        sa.Column('token_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('scopes', sa.Text(), server_default='', nullable=False),
        sa.Column('extra', sa.JSON(), server_default=sa.text("'{}'"), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'provider', 'provider_account_id', name='uq_connection_identity'),
    )
    with op.batch_alter_table('connected_providers', schema=None) as batch_op:
        batch_op.create_index('ix_connected_providers_user', ['user_id'], unique=False)

    op.create_table(
        'oauth_states',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('provider', sa.String(length=16), nullable=False),
        sa.Column('state_hash', sa.String(length=64), nullable=False),
        sa.Column('browser_hash', sa.String(length=64), nullable=False),
        sa.Column('code_verifier_encrypted', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('state_hash'),
    )
    with op.batch_alter_table('oauth_states', schema=None) as batch_op:
        batch_op.create_index('ix_oauth_states_user', ['user_id'], unique=False)

    with op.batch_alter_table('domains', schema=None) as batch_op:
        batch_op.add_column(sa.Column('provider', sa.String(length=16), nullable=True))
        batch_op.add_column(sa.Column('provider_connection_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('provider_project_id', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('provider_resource_id', sa.Text(), nullable=True))
        # Named, so the downgrade can find it (an unnamed constraint cannot be dropped).
        batch_op.create_foreign_key(
            'fk_domains_provider_connection_id', 'connected_providers', ['provider_connection_id'], ['id']
        )


def downgrade() -> None:
    with op.batch_alter_table('domains', schema=None) as batch_op:
        batch_op.drop_constraint('fk_domains_provider_connection_id', type_='foreignkey')
        batch_op.drop_column('provider_resource_id')
        batch_op.drop_column('provider_project_id')
        batch_op.drop_column('provider_connection_id')
        batch_op.drop_column('provider')

    with op.batch_alter_table('oauth_states', schema=None) as batch_op:
        batch_op.drop_index('ix_oauth_states_user')
    op.drop_table('oauth_states')

    with op.batch_alter_table('connected_providers', schema=None) as batch_op:
        batch_op.drop_index('ix_connected_providers_user')
    op.drop_table('connected_providers')
