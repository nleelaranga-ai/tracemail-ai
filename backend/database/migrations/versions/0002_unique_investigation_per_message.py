"""Add unique constraint on inbox_scan_results and owner_user_id columns

Revision ID: 0002_unique_investigation_per_message
Revises: 0001_initial_schema
Create Date: 2026-09-13 21:10:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0002_unique_investigation_per_message'
down_revision: Union[str, None] = '0001_initial_schema'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add owner_user_id to gmail_accounts
    try:
        op.add_column('gmail_accounts', sa.Column('owner_user_id', sa.String(length=64), nullable=True))
        op.create_index('ix_gmail_accounts_owner_user_id', 'gmail_accounts', ['owner_user_id'], unique=False)
    except Exception:
        pass

    # 2. Add owner_user_id to investigations
    try:
        op.add_column('investigations', sa.Column('owner_user_id', sa.String(length=64), nullable=True))
        op.create_index('ix_investigations_owner_user_id', 'investigations', ['owner_user_id'], unique=False)
    except Exception:
        pass

    # 3. Create unique constraint on inbox_scan_results(account_email, message_id)
    try:
        op.create_unique_constraint(
            "uq_inbox_scan_account_message",
            "inbox_scan_results",
            ["account_email", "message_id"]
        )
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_constraint("uq_inbox_scan_account_message", "inbox_scan_results", type_="unique")
    except Exception:
        pass

    try:
        op.drop_index('ix_investigations_owner_user_id', table_name='investigations')
        op.drop_column('investigations', 'owner_user_id')
    except Exception:
        pass

    try:
        op.drop_index('ix_gmail_accounts_owner_user_id', table_name='gmail_accounts')
        op.drop_column('gmail_accounts', 'owner_user_id')
    except Exception:
        pass
