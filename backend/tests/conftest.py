"""Shared pytest fixtures for the PortWatch Pro backend."""

import os
import sys
import tempfile

os.environ["PORTWATCH_SIMULATE"] = "1"
os.environ["PORTWATCH_SCHEDULER"] = "0"
os.environ["PORTWATCH_NO_DEFAULT_APP"] = "1"

BACKEND = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

import pytest  # noqa: E402

from app import create_app          # noqa: E402  (also wires the short-name import paths)
from core.config import Config      # noqa: E402
from core.ratelimit import limiter  # noqa: E402


class TestConfig(Config):
    TESTING = True
    ENV = "test"
    IS_PRODUCTION = False
    SIMULATE_SCANS = True
    SCHEDULER_ENABLED = False
    SCAN_JOBS_INLINE = True          # scans complete inside the request
    RATELIMIT_ENABLED = False        # enabled per-test where it is the subject
    JWT_EXPIRY_HOURS = 1
    SECRET_KEY = "unit-test-secret-key-not-for-production"
    SQLALCHEMY_DATABASE_URI = "sqlite://"  # placeholder, overridden per app


def make_app(**overrides):
    tmp = tempfile.mkdtemp()
    attrs = {"SQLALCHEMY_DATABASE_URI": f"sqlite:///{os.path.join(tmp, 'test.db')}"}
    attrs.update(overrides)
    cfg = type("Cfg", (TestConfig,), attrs)
    return create_app(cfg)


@pytest.fixture()
def app():
    limiter.reset()
    application = make_app()
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth(client):
    """Register a user and return (headers, session_json)."""
    def _make(email="a@t.io", name="Analyst", password="password123"):
        r = client.post("/api/auth/register",
                        json={"email": email, "name": name, "password": password})
        assert r.status_code == 201, r.get_json()
        body = r.get_json()
        return {"Authorization": f"Bearer {body['token']}"}, body
    return _make


@pytest.fixture()
def project(client, auth):
    headers, session = auth()
    r = client.post("/api/projects", json={"name": "Proj A", "description": "d"}, headers=headers)
    assert r.status_code == 201
    return headers, session, r.get_json()


def scan_payload(project_id, target="api.acme.com", profile="deep", **extra):
    payload = {"project_id": project_id, "target": target, "profile": profile,
               "authorised": True}
    payload.update(extra)
    return payload
