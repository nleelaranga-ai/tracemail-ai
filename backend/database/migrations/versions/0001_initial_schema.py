"""Initial schema creation for TraceMail AI

Revision ID: 0001_initial_schema
Revises: 
Create Date: 2026-09-13 17:25:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '0001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=True),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=False)

    # 2. investigations
    op.create_table(
        'investigations',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('sender', sa.String(length=255), nullable=True),
        sa.Column('recipient', sa.String(length=255), nullable=True),
        sa.Column('subject', sa.String(length=500), nullable=True),
        sa.Column('received_at', sa.DateTime(), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('country', sa.String(length=100), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=True),
        sa.Column('latitude', sa.JSON(), nullable=True),
        sa.Column('longitude', sa.JSON(), nullable=True),
        sa.Column('phishing_score', sa.Integer(), nullable=False),
        sa.Column('verdict', sa.String(length=50), nullable=False),
        sa.Column('risk_level', sa.String(length=50), nullable=False),
        sa.Column('explanation', sa.Text(), nullable=True),
        sa.Column('ai_summary', sa.Text(), nullable=True),
        sa.Column('raw_headers', sa.Text(), nullable=True),
        sa.Column('body_text', sa.Text(), nullable=True),
        sa.Column('entities', sa.JSON(), nullable=True),
        sa.Column('auth_results', sa.JSON(), nullable=True),
        sa.Column('hop_timeline', sa.JSON(), nullable=True),
        sa.Column('timeline', sa.JSON(), nullable=True),
        sa.Column('geojson_map', sa.JSON(), nullable=True),
        sa.Column('attack_graph', sa.JSON(), nullable=True),
        sa.Column('threat_results', sa.JSON(), nullable=True),
        sa.Column('virus_total', sa.JSON(), nullable=True),
        sa.Column('abuse_ipdb', sa.JSON(), nullable=True),
        sa.Column('whois', sa.JSON(), nullable=True),
        sa.Column('dns', sa.JSON(), nullable=True),
        sa.Column('urlscan', sa.JSON(), nullable=True),
        sa.Column('google_safe_browsing', sa.JSON(), nullable=True),
        sa.Column('ai_analysis', sa.JSON(), nullable=True),
        sa.Column('ioc', sa.JSON(), nullable=True),
        sa.Column('evidence_hash', sa.String(length=64), nullable=True),
        sa.Column('action_items', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_investigations_id'), 'investigations', ['id'], unique=False)

    # 3. emails
    op.create_table(
        'emails',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('sender', sa.String(length=255), nullable=True),
        sa.Column('recipient', sa.String(length=255), nullable=True),
        sa.Column('subject', sa.String(length=500), nullable=True),
        sa.Column('message_id', sa.String(length=255), nullable=True),
        sa.Column('reply_to', sa.String(length=255), nullable=True),
        sa.Column('raw_eml', sa.Text(), nullable=True),
        sa.Column('body_plain', sa.Text(), nullable=True),
        sa.Column('body_html', sa.Text(), nullable=True),
        sa.Column('date_sent', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_emails_id'), 'emails', ['id'], unique=False)
    op.create_index(op.f('ix_emails_scan_id'), 'emails', ['scan_id'], unique=False)

    # 4. headers
    op.create_table(
        'headers',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('header_name', sa.String(length=255), nullable=False),
        sa.Column('header_value', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_headers_id'), 'headers', ['id'], unique=False)
    op.create_index(op.f('ix_headers_scan_id'), 'headers', ['scan_id'], unique=False)

    # 5. threat_results
    op.create_table(
        'threat_results',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.String(length=64), nullable=True),
        sa.Column('indicator_type', sa.String(length=32), nullable=False),
        sa.Column('indicator_value', sa.String(length=500), nullable=False),
        sa.Column('reputation_score', sa.Integer(), nullable=False),
        sa.Column('is_malicious', sa.Boolean(), nullable=False),
        sa.Column('geo_location', sa.String(length=255), nullable=True),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_threat_results_id'), 'threat_results', ['id'], unique=False)
    op.create_index(op.f('ix_threat_results_investigation_id'), 'threat_results', ['investigation_id'], unique=False)

    # 6. ioc_entities
    op.create_table(
        'ioc_entities',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('ioc_type', sa.String(length=32), nullable=False),
        sa.Column('ioc_value', sa.String(length=500), nullable=False),
        sa.Column('threat_score', sa.Integer(), nullable=False),
        sa.Column('is_malicious', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ioc_entities_id'), 'ioc_entities', ['id'], unique=False)
    op.create_index(op.f('ix_ioc_entities_scan_id'), 'ioc_entities', ['scan_id'], unique=False)

    # 7. reports
    op.create_table(
        'reports',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.String(length=64), nullable=False),
        sa.Column('report_format', sa.String(length=16), nullable=False),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('download_count', sa.Integer(), nullable=False),
        sa.Column('generated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_reports_id'), 'reports', ['id'], unique=False)
    op.create_index(op.f('ix_reports_investigation_id'), 'reports', ['investigation_id'], unique=False)

    # 8. scans
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('sender', sa.String(length=255), nullable=True),
        sa.Column('domain', sa.String(length=255), nullable=True),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('country', sa.String(length=100), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=True),
        sa.Column('latitude', sa.JSON(), nullable=True),
        sa.Column('longitude', sa.JSON(), nullable=True),
        sa.Column('threat_score', sa.Integer(), nullable=False),
        sa.Column('risk_level', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_id'), 'scans', ['id'], unique=False)
    op.create_index(op.f('ix_scans_scan_id'), 'scans', ['scan_id'], unique=False)

    # 9. ai_results
    op.create_table(
        'ai_results',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('prediction', sa.String(length=50), nullable=False),
        sa.Column('confidence', sa.JSON(), nullable=False),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('reasons_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ai_results_id'), 'ai_results', ['id'], unique=False)
    op.create_index(op.f('ix_ai_results_scan_id'), 'ai_results', ['scan_id'], unique=False)

    # 10. audit_logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=64), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('target_id', sa.String(length=100), nullable=True),
        sa.Column('ip_address', sa.String(length=64), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_id'), 'audit_logs', ['id'], unique=False)

    # 11. investigation_geo_cache
    op.create_table(
        'investigation_geo_cache',
        sa.Column('key', sa.String(length=255), nullable=False),
        sa.Column('cache_type', sa.String(length=50), nullable=True),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('key')
    )
    op.create_index(op.f('ix_investigation_geo_cache_key'), 'investigation_geo_cache', ['key'], unique=False)
    op.create_index(op.f('ix_investigation_geo_cache_cache_type'), 'investigation_geo_cache', ['cache_type'], unique=False)

    # 12. gmail_accounts
    op.create_table(
        'gmail_accounts',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('access_token', sa.Text(), nullable=False),
        sa.Column('refresh_token', sa.Text(), nullable=True),
        sa.Column('token_expiry', sa.DateTime(), nullable=True),
        sa.Column('connected', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_scanned_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_gmail_accounts_id'), 'gmail_accounts', ['id'], unique=False)
    op.create_index(op.f('ix_gmail_accounts_email'), 'gmail_accounts', ['email'], unique=True)

    # 13. inbox_scan_results
    op.create_table(
        'inbox_scan_results',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('account_email', sa.String(length=255), nullable=False),
        sa.Column('message_id', sa.String(length=255), nullable=False),
        sa.Column('sender', sa.String(length=255), nullable=False),
        sa.Column('subject', sa.String(length=500), nullable=False),
        sa.Column('snippet', sa.Text(), nullable=True),
        sa.Column('risk', sa.String(length=50), nullable=False),
        sa.Column('threat_score', sa.Integer(), nullable=False),
        sa.Column('verdict', sa.String(length=50), nullable=False),
        sa.Column('scanned_at', sa.DateTime(), nullable=False),
        sa.Column('investigation_id', sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_inbox_scan_results_id'), 'inbox_scan_results', ['id'], unique=False)
    op.create_index(op.f('ix_inbox_scan_results_account_email'), 'inbox_scan_results', ['account_email'], unique=False)

    # 14. evidence_records
    op.create_table(
        'evidence_records',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.String(length=64), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('original_hash', sa.String(length=64), nullable=False),
        sa.Column('investigator', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('raw_content', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('custody_notes', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_evidence_records_id'), 'evidence_records', ['id'], unique=False)
    op.create_index(op.f('ix_evidence_records_investigation_id'), 'evidence_records', ['investigation_id'], unique=False)

    # 15. attachment_scans
    op.create_table(
        'attachment_scans',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('investigation_id', sa.String(length=64), nullable=True),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('file_type', sa.String(length=50), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False),
        sa.Column('malicious', sa.Boolean(), nullable=False),
        sa.Column('verdict', sa.String(length=50), nullable=False),
        sa.Column('engine', sa.String(length=100), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_attachment_scans_id'), 'attachment_scans', ['id'], unique=False)
    op.create_index(op.f('ix_attachment_scans_investigation_id'), 'attachment_scans', ['investigation_id'], unique=False)

    # 16. org_metrics
    op.create_table(
        'org_metrics',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('department', sa.String(length=100), nullable=False),
        sa.Column('threat_count', sa.Integer(), nullable=False),
        sa.Column('phishing_count', sa.Integer(), nullable=False),
        sa.Column('safe_count', sa.Integer(), nullable=False),
        sa.Column('risk_level', sa.String(length=50), nullable=False),
        sa.Column('top_attack_type', sa.String(length=100), nullable=False),
        sa.Column('last_attack_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('department')
    )
    op.create_index(op.f('ix_org_metrics_id'), 'org_metrics', ['id'], unique=False)


def downgrade() -> None:
    op.drop_table('org_metrics')
    op.drop_table('attachment_scans')
    op.drop_table('evidence_records')
    op.drop_table('inbox_scan_results')
    op.drop_table('gmail_accounts')
    op.drop_table('investigation_geo_cache')
    op.drop_table('audit_logs')
    op.drop_table('ai_results')
    op.drop_table('scans')
    op.drop_table('reports')
    op.create_index(op.f('ix_ioc_entities_scan_id'), 'ioc_entities', ['scan_id'], unique=False)
    op.drop_table('ioc_entities')
    op.drop_table('threat_results')
    op.drop_table('headers')
    op.drop_table('emails')
    op.drop_table('investigations')
    op.drop_table('users')
