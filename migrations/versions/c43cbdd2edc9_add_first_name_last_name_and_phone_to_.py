"""Add first_name, last_name, and phone to User model

Revision ID: c43cbdd2edc9
Revises: dc4200fcf067
Create Date: 2024-06-23 02:09:58.027457

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c43cbdd2edc9'
down_revision = 'dc4200fcf067'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('message') as batch_op:
        batch_op.add_column(sa.Column('author_id', sa.Integer(), nullable=True))
        batch_op.alter_column('body', existing_type=sa.TEXT(), nullable=True)
        batch_op.alter_column('recipient_id', existing_type=sa.INTEGER(), nullable=True)
        batch_op.alter_column('aes_algorithm', existing_type=sa.VARCHAR(length=50), type_=sa.String(length=64), nullable=True)
        batch_op.alter_column('aes_key', existing_type=sa.VARCHAR(length=200), type_=sa.String(length=64), nullable=True)
        batch_op.alter_column('aes_iv', existing_type=sa.VARCHAR(length=200), type_=sa.String(length=64), nullable=True)
        batch_op.drop_constraint('fk_message_sender_id_user', type_='foreignkey')
        batch_op.create_foreign_key('fk_message_author_id_user', 'user', ['author_id'], ['id'])
        batch_op.drop_column('sender_id')

    with op.batch_alter_table('user') as batch_op:
        batch_op.add_column(sa.Column('first_name', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('last_name', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('phone', sa.String(length=20), nullable=False))
        batch_op.alter_column('username', existing_type=sa.VARCHAR(length=64), nullable=True)
        batch_op.alter_column('email', existing_type=sa.VARCHAR(length=120), nullable=True)
        batch_op.alter_column('password_hash', existing_type=sa.VARCHAR(length=128), nullable=True)
        batch_op.create_index(op.f('ix_user_email'), ['email'], unique=True)
        batch_op.create_index(op.f('ix_user_username'), ['username'], unique=True)

def downgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.drop_index(op.f('ix_user_username'))
        batch_op.drop_index(op.f('ix_user_email'))
        batch_op.drop_column('phone')
        batch_op.drop_column('last_name')
        batch_op.drop_column('first_name')
        batch_op.alter_column('password_hash', existing_type=sa.VARCHAR(length=128), nullable=False)
        batch_op.alter_column('email', existing_type=sa.VARCHAR(length=120), nullable=False)
        batch_op.alter_column('username', existing_type=sa.VARCHAR(length=64), nullable=False)

    with op.batch_alter_table('message') as batch_op:
        batch_op.add_column(sa.Column('sender_id', sa.Integer(), nullable=False))
        batch_op.drop_constraint('fk_message_author_id_user', type_='foreignkey')
        batch_op.create_foreign_key('fk_message_sender_id_user', 'user', ['sender_id'], ['id'])
        batch_op.alter_column('aes_iv', existing_type=sa.String(length=64), type_=sa.VARCHAR(length=200), nullable=False)
        batch_op.alter_column('aes_key', existing_type=sa.String(length=64), type_=sa.VARCHAR(length=200), nullable=False)
        batch_op.alter_column('aes_algorithm', existing_type=sa.String(length=64), type_=sa.VARCHAR(length=50), nullable=False)
        batch_op.alter_column('recipient_id', existing_type=sa.INTEGER(), nullable=False)
        batch_op.alter_column('body', existing_type=sa.TEXT(), nullable=False)
        batch_op.drop_column('author_id')
