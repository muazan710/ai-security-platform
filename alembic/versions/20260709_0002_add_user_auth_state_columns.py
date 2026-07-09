"""add user auth state columns

Revision ID: 20260709_0002
Revises: 20260709_0001
Create Date: 2026-07-09
"""
from typing import Sequence, Union

from alembic import op


revision: str = "20260709_0002"
down_revision: Union[str, None] = "20260709_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_otp_sent TIMESTAMP NULL;")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0;")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS lock_until TIMESTAMP NULL;")
    op.execute("UPDATE users SET failed_login_attempts = 0 WHERE failed_login_attempts IS NULL;")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS lock_until;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS failed_login_attempts;")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS last_otp_sent;")
