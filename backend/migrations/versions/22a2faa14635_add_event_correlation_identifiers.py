"""add event correlation identifiers

Revision ID: 22a2faa14635
Revises: 5935a40bb9ff
Create Date: 2026-10-19 16:25:23.253722
"""
import uuid
from alembic import op
import sqlalchemy as sa

revision = '22a2faa14635'
down_revision = '5935a40bb9ff'
branch_labels = None
depends_on = None

def _add_and_backfill(table:str):
    op.add_column(table,sa.Column('correlation_id',sa.String(length=36),nullable=True))
    connection=op.get_bind()
    rows=connection.execute(sa.text(f'SELECT id FROM {table} WHERE correlation_id IS NULL')).all()
    for (row_id,) in rows:
        connection.execute(sa.text(f'UPDATE {table} SET correlation_id = :correlation WHERE id = :row_id'),{'correlation':str(uuid.uuid4()),'row_id':row_id})
    with op.batch_alter_table(table) as batch:
        batch.alter_column('correlation_id',existing_type=sa.String(length=36),nullable=False)
    op.create_index(op.f(f'ix_{table}_correlation_id'),table,['correlation_id'],unique=False)

def upgrade():
    # Backfill each historical record before enforcing NOT NULL; no existing events are dropped.
    _add_and_backfill('login_events')
    _add_and_backfill('risk_events')

def downgrade():
    op.drop_index(op.f('ix_risk_events_correlation_id'),table_name='risk_events')
    op.drop_column('risk_events','correlation_id')
    op.drop_index(op.f('ix_login_events_correlation_id'),table_name='login_events')
    op.drop_column('login_events','correlation_id')
