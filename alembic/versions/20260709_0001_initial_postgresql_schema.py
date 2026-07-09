"""initial PostgreSQL schema

Revision ID: 20260709_0001
Revises:
Create Date: 2026-07-09
"""
from typing import Sequence, Union

from alembic import op


revision: str = "20260709_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'userrole') THEN
                CREATE TYPE userrole AS ENUM ('USER', 'ADMIN');
            END IF;
        END
        $$;
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR UNIQUE NOT NULL,
            password_hash VARCHAR NOT NULL,
            api_key_hash VARCHAR NOT NULL,
            api_key_prefix VARCHAR NOT NULL,
            api_key_created_at TIMESTAMP NULL,
            is_active BOOLEAN,
            is_admin BOOLEAN,
            role userrole,
            usage_count INTEGER,
            created_at TIMESTAMP NULL,
            updated_at TIMESTAMP NULL,
            last_login TIMESTAMP NULL,
            email_verified BOOLEAN,
            email_otp VARCHAR NULL,
            otp_expiry TIMESTAMP NULL,
            otp_attempts INTEGER
        );
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS prediction_history (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            url TEXT NOT NULL,
            prediction VARCHAR NOT NULL,
            confidence FLOAT NOT NULL,
            risk_level VARCHAR NOT NULL,
            ai_agent TEXT NULL,
            virustotal TEXT NULL,
            threat_intelligence TEXT NULL,
            feature_summary TEXT NULL,
            domain_age INTEGER NULL,
            domain_exists BOOLEAN,
            rule_override BOOLEAN,
            risk_factors TEXT NULL,
            risk_score INTEGER NULL,
            scan_duration FLOAT NULL,
            created_at TIMESTAMP NULL
        );
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS prediction_model_results (
            id SERIAL PRIMARY KEY,
            history_id INTEGER NOT NULL REFERENCES prediction_history(id) ON DELETE CASCADE,
            model_name VARCHAR NOT NULL,
            prediction VARCHAR NOT NULL,
            confidence FLOAT NOT NULL,
            execution_time FLOAT NULL,
            feature_summary TEXT NULL,
            domain_age INTEGER NULL,
            domain_exists BOOLEAN,
            rule_override BOOLEAN,
            risk_factors TEXT NULL,
            created_at TIMESTAMP NULL
        );
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            action VARCHAR NOT NULL,
            details TEXT NULL,
            ip_address VARCHAR NULL,
            user_agent VARCHAR NULL,
            created_at TIMESTAMP NULL
        );
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS api_key_logs (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            action VARCHAR NOT NULL,
            api_key_hash VARCHAR NULL,
            ip_address VARCHAR NULL,
            created_at TIMESTAMP NULL
        );
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_email ON users (email);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_api_key_hash ON users (api_key_hash);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_prediction_history_user_id ON prediction_history (user_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_prediction_history_user_created ON prediction_history (user_id, created_at);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_prediction_model_results_history_id ON prediction_model_results (history_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_prediction_model_results_history_model ON prediction_model_results (history_id, model_name);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_logs_user_id ON audit_logs (user_id);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_logs_user_created ON audit_logs (user_id, created_at);")
    op.execute("CREATE INDEX IF NOT EXISTS ix_api_key_logs_user_id ON api_key_logs (user_id);")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS api_key_logs;")
    op.execute("DROP TABLE IF EXISTS audit_logs;")
    op.execute("DROP TABLE IF EXISTS prediction_model_results;")
    op.execute("DROP TABLE IF EXISTS prediction_history;")
    op.execute("DROP TABLE IF EXISTS users;")
    op.execute("DROP TYPE IF EXISTS userrole;")
