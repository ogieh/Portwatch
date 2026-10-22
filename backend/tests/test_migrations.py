"""Schema management: fresh databases, and legacy 2.0 databases created with
db.create_all() and no Alembic history."""

import os
import tempfile

import sqlalchemy as sa

from conftest import make_app


def _legacy_db(path):
    """Create the exact 2.0 schema (what the old create_all produced) plus a row."""
    engine = sa.create_engine(f"sqlite:///{path}")
    with engine.begin() as c:
        c.exec_driver_sql("""CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(255) NOT NULL,
            name VARCHAR(120) NOT NULL, password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL, created_at DATETIME)""")
        c.exec_driver_sql("CREATE UNIQUE INDEX ix_users_email ON users (email)")
        c.exec_driver_sql("""CREATE TABLE projects (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
            name VARCHAR(150) NOT NULL, description TEXT, created_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES users (id))""")
        c.exec_driver_sql("""CREATE TABLE scans (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL,
            target VARCHAR(255) NOT NULL, profile VARCHAR(20) NOT NULL, timestamp DATETIME,
            summary TEXT, risk_score INTEGER, risk_grade VARCHAR(2), trigger VARCHAR(20),
            full_data TEXT NOT NULL, FOREIGN KEY(project_id) REFERENCES projects (id))""")
        c.exec_driver_sql("""CREATE TABLE schedules (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL,
            project_id INTEGER NOT NULL, target VARCHAR(255) NOT NULL, profile VARCHAR(20) NOT NULL,
            credential_checks BOOLEAN, interval_hours INTEGER NOT NULL, enabled BOOLEAN,
            last_run DATETIME, next_run DATETIME, created_at DATETIME)""")
        c.exec_driver_sql("""CREATE TABLE notification_channels (id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL, kind VARCHAR(20) NOT NULL, target VARCHAR(500) NOT NULL,
            min_grade VARCHAR(2), enabled BOOLEAN, created_at DATETIME)""")
        c.exec_driver_sql("INSERT INTO users VALUES (1,'old@t.io','Old','scrypt:x','admin',NULL)")
        c.exec_driver_sql("INSERT INTO projects VALUES (1,1,'Legacy','',NULL)")
        c.exec_driver_sql("""INSERT INTO scans VALUES (1,1,'legacy.example','standard',NULL,'s',88,'B',
            'manual','{"ports":[],"risk":{"score":88,"grade":"B"}}')""")
        c.exec_driver_sql("INSERT INTO schedules VALUES (1,1,1,'legacy.example','quick',0,24,1,NULL,NULL,NULL)")
    engine.dispose()


def test_legacy_database_is_stamped_and_upgraded():
    path = os.path.join(tempfile.mkdtemp(), "legacy.db")
    _legacy_db(path)
    app = make_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{path}")
    with app.app_context():
        from models.db import db, Scan, Schedule, Project
        from core.migrate import current_revision
        insp = sa.inspect(db.engine)
        assert "audit_log" in insp.get_table_names()
        cols = {c["name"] for c in insp.get_columns("scans")}
        assert {"status", "authorised", "started_at", "requested_by"} <= cols
        with db.engine.connect() as conn:
            assert current_revision(conn) == "0002_hardening"
        # Back-fill semantics.
        s = db.session.get(Scan, 1)
        assert s.status == "completed" and s.authorised is False
        assert s.get_full()["risk"]["grade"] == "B"
        assert db.session.get(Schedule, 1).authorised is False
        assert db.session.get(Project, 1).allowlist() == []
    # Booting again is a no-op.
    make_app(SQLALCHEMY_DATABASE_URI=f"sqlite:///{path}")


def test_fresh_database_has_full_schema(app):
    with app.app_context():
        from models.db import db
        names = set(sa.inspect(db.engine).get_table_names())
    assert {"users", "projects", "scans", "schedules", "notification_channels", "refresh_tokens",
            "password_reset_tokens", "api_keys", "audit_log", "alembic_version"} <= names


def test_downgrade_and_upgrade_round_trip(app):
    from alembic import command
    from core.migrate import _alembic_config, current_revision
    from models.db import db
    with app.app_context():
        with db.engine.begin() as conn:
            cfg = _alembic_config(conn)
            command.downgrade(cfg, "0001_baseline")
            assert current_revision(conn) == "0001_baseline"
            assert "audit_log" not in sa.inspect(conn).get_table_names()
            command.upgrade(cfg, "head")
            assert current_revision(conn) == "0002_hardening"


def test_production_refuses_default_secret():
    import pytest
    from core.config import Config, validate
    class Prod(Config):
        IS_PRODUCTION = True
    with pytest.raises(RuntimeError):
        validate(Prod)
    class Ok(Prod):
        SECRET_KEY = "a-long-enough-random-secret-value"
    assert validate(Ok) == [] or all("SQLite" in w for w in validate(Ok))
    class Dev(Config):
        IS_PRODUCTION = False
    assert any("PORTWATCH_SECRET" in w for w in validate(Dev))
