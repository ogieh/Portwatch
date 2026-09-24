"""Alembic environment for PortWatch Pro.

Works two ways:
  - CLI:  cd backend && alembic upgrade head   (URL from PORTWATCH_DB_URI)
  - App:  core.migrate.upgrade_to_head() passes the live engine in
          config.attributes["connection"] so the app and Alembic share one
          connection and one URL.
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

HERE = os.path.abspath(os.path.dirname(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, ".."))
for sub in ("", "core", "api", "services", "models"):
    p = os.path.join(BACKEND, sub)
    if p not in sys.path:
        sys.path.insert(0, p)

config = context.config
if config.config_file_name is not None and not config.attributes.get("connection"):
    fileConfig(config.config_file_name)

from models.db import db  # noqa: E402

target_metadata = db.metadata


def _url():
    return os.environ.get("PORTWATCH_DB_URI") or config.get_main_option("sqlalchemy.url")


def run_migrations_offline():
    context.configure(url=_url(), target_metadata=target_metadata,
                      literal_binds=True, render_as_batch=True,
                      dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connection = config.attributes.get("connection")
    if connection is not None:
        context.configure(connection=connection, target_metadata=target_metadata,
                          render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()
        return

    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata,
                          render_as_batch=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
