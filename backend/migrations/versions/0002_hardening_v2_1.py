"""2.1 hardening: consent + scan lifecycle, allowlists, refresh/reset tokens,
API keys, audit log.

Revision ID: 0002_hardening
Revises: 0001_baseline
Create Date: 2026-09-11

Existing rows are back-filled conservatively:
  - scans.status = 'completed' (every pre-2.1 scan finished inside its request)
  - scans.authorised / schedules.authorised = false (consent was never recorded,
    so it is not assumed; the scheduler disables unconsented schedules)
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_hardening"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as b:
        b.add_column(sa.Column("token_version", sa.Integer, nullable=False, server_default="0"))
        b.add_column(sa.Column("password_changed_at", sa.DateTime))

    with op.batch_alter_table("projects") as b:
        b.add_column(sa.Column("allowed_targets", sa.Text, server_default=""))

    with op.batch_alter_table("scans") as b:
        b.add_column(sa.Column("status", sa.String(20), nullable=False, server_default="completed"))
        b.add_column(sa.Column("error", sa.Text))
        b.add_column(sa.Column("started_at", sa.DateTime))
        b.add_column(sa.Column("finished_at", sa.DateTime))
        b.add_column(sa.Column("authorised", sa.Boolean, nullable=False, server_default=sa.false()))
        b.add_column(sa.Column("credential_checks", sa.Boolean, nullable=False, server_default=sa.false()))
        b.add_column(sa.Column("requested_by", sa.Integer))
        b.create_foreign_key("fk_scans_requested_by_users", "users",
                             ["requested_by"], ["id"], ondelete="SET NULL")
    op.create_index("ix_scans_status", "scans", ["status"])

    with op.batch_alter_table("schedules") as b:
        b.add_column(sa.Column("authorised", sa.Boolean, nullable=False, server_default=sa.false()))

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime),
        sa.Column("user_agent", sa.String(255)),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("ix_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)

    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("used_at", sa.DateTime),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"])
    op.create_index("ix_password_reset_tokens_token_hash", "password_reset_tokens",
                    ["token_hash"], unique=True)

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("hint", sa.String(12), nullable=False),
        sa.Column("key_hash", sa.String(64), nullable=False),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("last_used_at", sa.DateTime),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"], unique=True)

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("created_at", sa.DateTime),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("actor", sa.String(255)),
        sa.Column("action", sa.String(60), nullable=False),
        sa.Column("resource_type", sa.String(40)),
        sa.Column("resource_id", sa.Integer),
        sa.Column("detail", sa.Text),
        sa.Column("ip", sa.String(64)),
        sqlite_autoincrement=True,
    )
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])
    op.create_index("ix_audit_log_user_id", "audit_log", ["user_id"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])


def downgrade():
    for name in ("audit_log", "api_keys", "password_reset_tokens", "refresh_tokens"):
        op.drop_table(name)
    with op.batch_alter_table("schedules") as b:
        b.drop_column("authorised")
    op.drop_index("ix_scans_status", table_name="scans")
    with op.batch_alter_table("scans") as b:
        b.drop_constraint("fk_scans_requested_by_users", type_="foreignkey")
        for col in ("requested_by", "credential_checks", "authorised", "finished_at",
                    "started_at", "error", "status"):
            b.drop_column(col)
    with op.batch_alter_table("projects") as b:
        b.drop_column("allowed_targets")
    with op.batch_alter_table("users") as b:
        b.drop_column("password_changed_at")
        b.drop_column("token_version")
