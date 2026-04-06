"""add scan progress, error_detail; change exploit raw_output JSONB→JSON

Revision ID: a90596a1457f
Revises: 66f22baabbfb
Create Date: 2026-04-05 17:45:52.523235

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a90596a1457f'
down_revision: Union[str, Sequence[str], None] = '66f22baabbfb'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # ── Scan: add progress + error_detail ────────────────────────
    scan_columns = {col["name"] for col in inspector.get_columns("scan")}

    if "progress" not in scan_columns:
        op.add_column('scan', sa.Column('progress', sa.Integer(), nullable=False, server_default='0'))
        op.alter_column('scan', 'progress', server_default=None)

    if "error_detail" not in scan_columns:
        op.add_column('scan', sa.Column('error_detail', sa.String(), nullable=True))

    # ── Exploit: JSONB → JSON (PostgreSQL compatible, no-op on SQLite) ──
    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.alter_column(
            'exploit', 'raw_output',
            type_=sa.JSON(),
            existing_type=sa.dialects.postgresql.JSONB(),
            existing_nullable=True,
        )


def downgrade() -> None:
    """Downgrade schema."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    scan_columns = {col["name"] for col in inspector.get_columns("scan")}

    if "error_detail" in scan_columns:
        op.drop_column('scan', 'error_detail')
    if "progress" in scan_columns:
        op.drop_column('scan', 'progress')

    dialect = bind.dialect.name
    if dialect == "postgresql":
        op.alter_column(
            'exploit', 'raw_output',
            type_=sa.dialects.postgresql.JSONB(),
            existing_type=sa.JSON(),
            existing_nullable=True,
        )
