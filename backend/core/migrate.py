"""
Schema management for PortWatch Pro (Alembic, run from inside the app).

upgrade_to_head() handles the three states a database can be in:

  1. Empty                      -> run every migration.
  2. 2.0 tables, no Alembic     -> stamp 0001_baseline, then upgrade.
     (created by the old db.create_all(); its columns match 0001 exactly)
  3. Already under Alembic      -> upgrade whatever is pending.

It shares the app's SQLAlchemy engine, so it works for SQLite and PostgreSQL
alike and needs no alembic.ini lookup at runtime. The CLI still works for
manual control:  cd backend && alembic upgrade head
"""

import os

from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from sqlalchemy import inspect

from models.db import db

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BASELINE_REVISION = "0001_baseline"


def _alembic_config(connection):
    cfg = AlembicConfig(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "migrations"))
    cfg.attributes["connection"] = connection
    return cfg


def current_revision(connection):
    return MigrationContext.configure(connection).get_current_revision()


def upgrade_to_head(app):
    engine = db.engine
    with engine.begin() as connection:
        inspector = inspect(connection)
        tables = set(inspector.get_table_names())
        cfg = _alembic_config(connection)

        if "alembic_version" not in tables and "users" in tables:
            app.logger.info("Legacy 2.0 database detected; stamping %s", BASELINE_REVISION)
            command.stamp(cfg, BASELINE_REVISION)

        before = current_revision(connection)
        command.upgrade(cfg, "head")
        after = current_revision(connection)
        if before != after:
            app.logger.info("Database migrated %s -> %s", before or "(empty)", after)
        return after
