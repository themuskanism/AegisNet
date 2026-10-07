"""Initial persistent observation, incident, explanation, response and audit schema."""
from alembic import op
import sqlalchemy as sa
revision='0001'
down_revision=None
branch_labels=None
depends_on=None


def upgrade():
    op.create_table('observations',sa.Column('id',sa.String(40),primary_key=True),sa.Column('created',sa.Float,nullable=False),sa.Column('source',sa.String(64),nullable=False),sa.Column('provenance',sa.String(32),nullable=False),sa.Column('data',sa.JSON,nullable=False))
    op.create_table('incidents',sa.Column('id',sa.String(40),primary_key=True),sa.Column('flow_id',sa.String(40),sa.ForeignKey('observations.id'),unique=True,nullable=False),sa.Column('source',sa.String(64),nullable=False),sa.Column('created',sa.Float,nullable=False),sa.Column('status',sa.String(24),nullable=False),sa.Column('data',sa.JSON,nullable=False))
    op.create_table('explanations',sa.Column('id',sa.String(40),sa.ForeignKey('incidents.id'),primary_key=True),sa.Column('data',sa.JSON,nullable=False))
    op.create_table('actions',sa.Column('id',sa.String(40),primary_key=True),sa.Column('created',sa.Float,nullable=False),sa.Column('status',sa.String(24),nullable=False),sa.Column('data',sa.JSON,nullable=False))
    op.create_table('sources',sa.Column('ip',sa.String(64),primary_key=True),sa.Column('kind',sa.String(24),primary_key=True),sa.Column('data',sa.JSON,nullable=False))
    op.create_table('events',sa.Column('id',sa.String(40),primary_key=True),sa.Column('created',sa.Float,nullable=False),sa.Column('data',sa.JSON,nullable=False))
    op.create_table('models',sa.Column('id',sa.String(80),primary_key=True),sa.Column('data',sa.JSON,nullable=False))
    for table,columns in [('observations',['created','source','provenance']),('incidents',['created','source']),('actions',['created']),('events',['created'])]:
        for column in columns:op.create_index(f'ix_{table}_{column}',table,[column])


def downgrade():
    for table in ['models','events','sources','actions','explanations','incidents','observations']:op.drop_table(table)
