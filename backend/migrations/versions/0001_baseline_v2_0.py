"""Baseline: the PortWatch Pro 2.0 schema (users, projects, scans, schedules, channels).

Revision ID: 0001_baseline
Revises: None
Create Date: 2026-09-11

A database created by 2.0's db.create_all() already matches this revision;
core.migrate stamps such databases at 0001 before upgrading further.
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False, server_default="analyst"),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "projects",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("name", sa.String(150), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_projects_user_id", "projects", ["user_id"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("project_id", sa.Integer, sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("profile", sa.String(20), nullable=False, server_default="standard"),
        sa.Column("timestamp", sa.DateTime),
        sa.Column("summary", sa.Text),
        sa.Column("risk_score", sa.Integer),
        sa.Column("risk_grade", sa.String(2)),
        sa.Column("trigger", sa.String(20), server_default="manual"),
        sa.Column("full_data", sa.Text, nullable=False, server_default="{}"),
    )
    op.create_index("ix_scans_project_id", "scans", ["project_id"])
    op.create_index("ix_scans_timestamp", "scans", ["timestamp"])

    op.create_table(
        "schedules",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("project_id", sa.Integer, sa.ForeignKey("projects.id"), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("profile", sa.String(20), nullable=False, server_default="standard"),
        sa.Column("credential_checks", sa.Boolean),
        sa.Column("interval_hours", sa.Integer, nullable=False, server_default="24"),
        sa.Column("enabled", sa.Boolean),
        sa.Column("last_run", sa.DateTime),
        sa.Column("next_run", sa.DateTime),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_schedules_user_id", "schedules", ["user_id"])
    op.create_index("ix_schedules_next_run", "schedules", ["next_run"])

    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("min_grade", sa.String(2)),
        sa.Column("enabled", sa.Boolean),
        sa.Column("created_at", sa.DateTime),
    )
    op.create_index("ix_notification_channels_user_id", "notification_channels", ["user_id"])


def downgrade():
    for name in ("notification_channels", "schedules", "scans", "projects", "users"):
        op.drop_table(name)
