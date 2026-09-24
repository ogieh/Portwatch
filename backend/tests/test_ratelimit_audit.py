"""Rate limiting and the audit log."""

import pytest

from conftest import make_app, scan_payload
from core.ratelimit import RateLimiter, parse_limit, limiter


def test_parse_limit():
    assert parse_limit("10/minute") == (10, 60)
    assert parse_limit("3/second") == (3, 1)
    assert parse_limit("100/hour") == (100, 3600)
    with pytest.raises(ValueError):
        parse_limit("1/fortnight")


def test_limiter_windows():
    rl = RateLimiter()
    for i in range(3):
        allowed, remaining, _ = rl.hit("t", "k", 3, 60)
        assert allowed and remaining == 2 - i
    allowed, remaining, retry = rl.hit("t", "k", 3, 60)
    assert not allowed and retry >= 1
    assert rl.hit("t", "other", 3, 60)[0]


def test_login_is_rate_limited():
    limiter.reset()
    app = make_app(RATELIMIT_ENABLED=True, RATELIMIT_LOGIN="3/minute")
    c = app.test_client()
    c.post("/api/auth/register", json={"email": "a@t.io", "name": "A", "password": "password123"})
    for _ in range(3):
        r = c.post("/api/auth/login", json={"email": "a@t.io", "password": "wrong"})
        assert r.status_code == 401
        assert "X-RateLimit-Remaining" in r.headers
    r = c.post("/api/auth/login", json={"email": "a@t.io", "password": "password123"})
    assert r.status_code == 429 and "Retry-After" in r.headers
    # A different client IP is unaffected.
    r = c.post("/api/auth/login", json={"email": "a@t.io", "password": "password123"},
               headers={"X-Forwarded-For": "203.0.113.9"})
    assert r.status_code == 200


def test_scan_is_rate_limited_per_user():
    limiter.reset()
    app = make_app(RATELIMIT_ENABLED=True, RATELIMIT_SCAN="2/minute")
    c = app.test_client()
    r = c.post("/api/auth/register", json={"email": "a@t.io", "name": "A", "password": "password123"})
    H = {"Authorization": f"Bearer {r.get_json()['token']}"}
    pid = c.post("/api/projects", json={"name": "P"}, headers=H).get_json()["id"]
    assert c.post("/api/scan", json=scan_payload(pid), headers=H).status_code == 200
    assert c.post("/api/scan", json=scan_payload(pid), headers=H).status_code == 200
    assert c.post("/api/scan", json=scan_payload(pid), headers=H).status_code == 429


def test_audit_log_records_and_scopes(client, auth, project):
    HA, _, proj = project
    HB, _ = auth("b@t.io")
    client.post("/api/scan", json=scan_payload(proj["id"]), headers=HA)
    client.post("/api/auth/login", json={"email": "a@t.io", "password": "wrong"})

    # Admin (first user) sees everything, including the anonymous failed login.
    rows = client.get("/api/audit", headers=HA).get_json()
    actions = [r["action"] for r in rows]
    for expected in ("auth.register", "project.created", "scan.requested",
                     "scan.started", "scan.completed", "auth.login_failed"):
        assert expected in actions, expected
    scan_row = next(r for r in rows if r["action"] == "scan.completed")
    assert scan_row["resource_type"] == "Scan" and "grade=" in scan_row["detail"]

    # Analyst B sees only their own events.
    rows_b = client.get("/api/audit", headers=HB).get_json()
    assert rows_b and all(r["actor"] == "b@t.io" for r in rows_b)

    # Filter by action prefix.
    only_auth = client.get("/api/audit?action=auth.", headers=HA).get_json()
    assert only_auth and all(r["action"].startswith("auth.") for r in only_auth)


def test_audit_survives_user_deletion(app, client, auth):
    H, session = auth("gone@t.io")
    from models.db import db, User, AuditLog
    with app.app_context():
        u = User.query.filter_by(email="gone@t.io").first()
        db.session.delete(u)
        db.session.commit()
        rows = AuditLog.query.filter_by(actor="gone@t.io").all()
        assert rows, "audit rows must outlive the user"
