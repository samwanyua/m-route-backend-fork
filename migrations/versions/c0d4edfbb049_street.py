"""street

Revision ID: c0d4edfbb049
Revises: 5fdb34f75a4c
Create Date: 2024-05-10 15:43:30.208589

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c0d4edfbb049'
down_revision = '5fdb34f75a4c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('route_plans', schema=None) as batch_op:
        batch_op.alter_column('instructions',
               existing_type=sa.TEXT(),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('route_plans', schema=None) as batch_op:
        batch_op.alter_column('instructions',
               existing_type=sa.TEXT(),
               nullable=True)

    # ### end Alembic commands ###
