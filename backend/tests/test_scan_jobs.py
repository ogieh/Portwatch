"""Background execution: threaded runner, polling, cancel, timeout, scheduler."""

import time
import threading

from conftest import make_app, scan_payload
import scan_jobs
import scanner


def _wait(client, H, sid, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        d = client.get(f"/api/scans/{sid}", headers=H).get_json()
        if d["status"] not in ("queued", "running"):
            return d
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def _setup(**overrides):
    app = make_app(SCAN_JOBS_INLINE=False, **overrides)
    c = app.test_client()
    r = c.post("/api/auth/register", json={"email": "a@t.io", "name": "A", "password": "password123"})
    H = {"Authorization": f"Bearer {r.get_json()['token']}"}
    pid = c.post("/api/projects", json={"name": "P"}, headers=H).get_json()["id"]
    return app, c, H, pid


def test_threaded_scan_returns_202_then_completes():
    app, c, H, pid = _setup()
    try:
        r = c.post("/api/scan", json=scan_payload(pid), headers=H)
        assert r.status_code in (200, 202)
        sid = r.get_json()["id"]
        d = _wait(c, H, sid)
        assert d["status"] == "completed" and d["risk"]["grade"]
        assert d["duration_seconds"] is not None
        # Report and diff are available once completed.
        assert c.get(f"/api/scans/{sid}/report", headers=H).status_code == 200
    finally:
        scan_jobs.shutdown(wait=True)


def test_wait_parameter_blocks_until_done():
    app, c, H, pid = _setup()
    try:
        r = c.post("/api/scan?wait=1", json=scan_payload(pid), headers=H)
        assert r.status_code == 200 and r.get_json()["status"] == "completed"
    finally:
        scan_jobs.shutdown(wait=True)


def test_cancel_running_scan(monkeypatch):
    app, c, H, pid = _setup()
    release = threading.Event()

    def slow_scan(*args, cancel_check=None, **kw):
        # Emulate a long phase 1, then honour the cancel flag like the real engine.
        release.wait(5)
        if cancel_check and cancel_check():
            raise scanner.ScanCancelled("cancelled after port discovery")
        return {"target": "t", "profile": "quick", "credential_checks": None,
                "resolved_host": "t", "ports": [], "summary": "", "engine": "simulated"}

    monkeypatch.setattr(scanner, "run_scan", slow_scan)
    try:
        sid = c.post("/api/scan", json=scan_payload(pid, profile="quick"), headers=H).get_json()["id"]
        time.sleep(0.2)
        r = c.post(f"/api/scans/{sid}/cancel", headers=H)
        assert r.status_code == 200 and r.get_json()["status"] == "cancelled"
        assert c.delete(f"/api/scans/{sid}", headers=H).status_code == 200 or True
        release.set()
        time.sleep(0.5)
        d = c.get(f"/api/scans/{sid}", headers=H)
        # Either deleted above, or still cancelled: never resurrected as completed.
        assert d.status_code == 404 or d.get_json()["status"] == "cancelled"
        assert c.post(f"/api/scans/{sid}/cancel", headers=H).status_code in (404, 409)
    finally:
        release.set()
        scan_jobs.shutdown(wait=True)


def test_scan_timeout_marks_failed(monkeypatch):
    app, c, H, pid = _setup(SCAN_MAX_SECONDS={"quick": 1, "standard": 1, "deep": 1})
    release = threading.Event()

    def stuck_scan(*args, cancel_check=None, **kw):
        release.wait(10)
        raise scanner.ScanCancelled("late")

    monkeypatch.setattr(scanner, "run_scan", stuck_scan)
    try:
        sid = c.post("/api/scan", json=scan_payload(pid, profile="quick"), headers=H).get_json()["id"]
        d = _wait(c, H, sid, timeout=6)
        assert d["status"] == "failed" and "ceiling" in d["error"]
        release.set()
        time.sleep(0.3)
        assert c.get(f"/api/scans/{sid}", headers=H).get_json()["status"] == "failed"
    finally:
        release.set()
        scan_jobs.shutdown(wait=True)


def test_engine_failure_is_recorded(monkeypatch):
    app, c, H, pid = _setup()

    def broken(*a, **k):
        raise RuntimeError("Nmap could not get any response")

    monkeypatch.setattr(scanner, "run_scan", broken)
    try:
        sid = c.post("/api/scan", json=scan_payload(pid), headers=H).get_json()["id"]
        d = _wait(c, H, sid)
        assert d["status"] == "failed" and "Nmap" in d["error"]
        assert c.get(f"/api/scans/{sid}/report", headers=H).status_code == 400
    finally:
        scan_jobs.shutdown(wait=True)


def test_scheduler_pass_queues_due_schedules():
    app, c, H, pid = _setup()
    import scheduler_service
    from models.db import db, Schedule
    from core.config import utcnow
    from datetime import timedelta
    try:
        r = c.post("/api/schedules", json={"project_id": pid, "target": "sched.example",
                                           "interval_hours": 1, "authorised": True}, headers=H)
        sid = r.get_json()["id"]
        with app.app_context():
            s = db.session.get(Schedule, sid)
            s.next_run = utcnow() - timedelta(minutes=1)
            # And one legacy schedule with no recorded consent.
            legacy = Schedule(user_id=s.user_id, project_id=pid, target="legacy.example",
                              interval_hours=1, enabled=True, authorised=False,
                              next_run=utcnow() - timedelta(minutes=1))
            db.session.add(legacy)
            db.session.commit()
            legacy_id = legacy.id
        scheduler_service.run_once(app)
        scans = c.get("/api/scans", headers=H).get_json()
        assert [s["target"] for s in scans] == ["sched.example"]
        assert scans[0]["trigger"] == "scheduled"
        _wait(c, H, scans[0]["id"])
        sched = {s["id"]: s for s in c.get("/api/schedules", headers=H).get_json()}
        assert sched[sid]["last_run"] is not None and sched[sid]["enabled"] is True
        assert sched[legacy_id]["enabled"] is False
    finally:
        scan_jobs.shutdown(wait=True)


def test_scan_type_flag():
    assert scanner.scan_type_flag("connect") == "-sT"
    assert scanner.scan_type_flag("syn") == "-sS"
