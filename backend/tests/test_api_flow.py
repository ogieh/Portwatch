"""End-to-end API flow (the original 27-assertion suite, ported to pytest and
extended for the async scan lifecycle)."""

from conftest import scan_payload


def test_register_login_and_roles(client):
    r = client.post("/api/auth/register", json={"email": "a@t.io", "name": "A", "password": "password123"})
    assert r.status_code == 201
    body = r.get_json()
    assert "token" in body and "refresh_token" in body
    assert body["user"]["role"] == "admin"

    r = client.post("/api/auth/register", json={"email": "b@t.io", "name": "B", "password": "password123"})
    assert r.get_json()["user"]["role"] == "analyst"

    assert client.get("/api/projects").status_code == 401
    assert client.post("/api/auth/login", json={"email": "a@t.io", "password": "wrong"}).status_code == 401
    r = client.post("/api/auth/login", json={"email": "a@t.io", "password": "password123"})
    assert r.status_code == 200 and r.get_json()["user"]["email"] == "a@t.io"


def test_register_validation(client):
    assert client.post("/api/auth/register", json={"email": "bad", "name": "x", "password": "password123"}).status_code == 400
    assert client.post("/api/auth/register", json={"email": "x@y.io", "name": "", "password": "password123"}).status_code == 400
    assert client.post("/api/auth/register", json={"email": "x@y.io", "name": "x", "password": "short"}).status_code == 400
    client.post("/api/auth/register", json={"email": "x@y.io", "name": "x", "password": "password123"})
    assert client.post("/api/auth/register", json={"email": "x@y.io", "name": "x", "password": "password123"}).status_code == 409


def test_projects_and_ownership(client, auth):
    HA, _ = auth("a@t.io")
    HB, _ = auth("b@t.io")
    r = client.post("/api/projects", json={"name": "Proj A", "description": "d"}, headers=HA)
    assert r.status_code == 201
    pid = r.get_json()["id"]
    assert client.get(f"/api/projects/{pid}", headers=HB).status_code == 404
    assert client.get(f"/api/projects/{pid}", headers=HA).status_code == 200
    assert client.post("/api/projects", json={"name": ""}, headers=HA).status_code == 400
    r = client.patch(f"/api/projects/{pid}", json={"name": "Renamed"}, headers=HA)
    assert r.get_json()["name"] == "Renamed"
    assert client.delete(f"/api/projects/{pid}", headers=HB).status_code == 404
    assert client.delete(f"/api/projects/{pid}", headers=HA).status_code == 200


def test_scan_full_lifecycle(client, auth, project):
    HA, _, proj = project
    HB, _ = auth("b@t.io")
    pid = proj["id"]

    r = client.post("/api/scan", json=scan_payload(pid, credential_checks=True), headers=HA)
    assert r.status_code == 200, r.get_json()
    d = r.get_json()
    assert d["status"] == "completed"
    assert "grade" in d["risk"]
    assert isinstance(d["intel"], list)
    assert "counts" in d["intel_summary"]
    assert isinstance(d["compliance"], list)
    assert d["engine"] == "simulated"
    assert d["authorised"] is True
    assert d["duration_seconds"] is not None
    sid1 = d["id"]

    r = client.post("/api/scan", json=scan_payload(pid), headers=HA)
    sid2 = r.get_json()["id"]

    assert client.get(f"/api/scans/{sid1}", headers=HB).status_code == 404
    assert client.post("/api/scan", json={"project_id": pid, "authorised": True}, headers=HA).status_code == 400
    assert client.post("/api/scan", json=scan_payload(pid, profile="nope"), headers=HA).status_code == 400
    assert client.post("/api/scan", json=scan_payload(999), headers=HA).status_code == 404

    r = client.get(f"/api/scans/{sid1}/diff/{sid2}", headers=HA)
    assert r.status_code == 200 and "opened_ports" in r.get_json()

    r = client.get("/api/scans", headers=HA)
    assert [s["id"] for s in r.get_json()] == [sid2, sid1]
    assert len(client.get(f"/api/scans?project_id={pid}", headers=HA).get_json()) == 2
    assert client.get("/api/scans", headers=HB).get_json() == []

    r = client.get(f"/api/scans/{sid1}/report", headers=HA)
    body = r.get_data(as_text=True)
    assert r.status_code == 200
    assert "Vulnerability Intelligence" in body and "OWASP" in body

    assert client.delete(f"/api/scans/{sid1}", headers=HB).status_code == 404
    assert client.delete(f"/api/scans/{sid1}", headers=HA).status_code == 200
    assert client.get(f"/api/scans/{sid1}", headers=HA).status_code == 404


def test_dashboard(client, project):
    HA, _, proj = project
    for t in ("a.example", "b.example"):
        client.post("/api/scan", json=scan_payload(proj["id"], target=t), headers=HA)
    d = client.get("/api/dashboard", headers=HA).get_json()
    assert d["kpis"]["total_scans"] == 2
    assert isinstance(d["score_trend"], list) and len(d["score_trend"]) == 2
    assert isinstance(d["grade_distribution"], dict)
    assert isinstance(d["recent_scans"], list)


def test_schedules(client, project):
    HA, _, proj = project
    pid = proj["id"]
    r = client.post("/api/schedules", json={"project_id": pid, "target": "api.acme.com",
                                            "profile": "quick", "interval_hours": 6,
                                            "authorised": True}, headers=HA)
    assert r.status_code == 201, r.get_json()
    schid = r.get_json()["id"]
    assert r.get_json()["authorised"] is True
    assert client.post("/api/schedules", json={"project_id": pid, "target": "x",
                                               "interval_hours": 9999, "authorised": True},
                       headers=HA).status_code == 400
    r = client.post(f"/api/schedules/{schid}/run", json={}, headers=HA)
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["scan"]["trigger"] == "scheduled"
    assert r.get_json()["scan"]["status"] == "completed"
    r = client.patch(f"/api/schedules/{schid}", json={"enabled": False}, headers=HA)
    assert r.get_json()["enabled"] is False
    assert len(client.get("/api/schedules", headers=HA).get_json()) == 1
    assert client.delete(f"/api/schedules/{schid}", headers=HA).status_code == 200


def test_notifications(client, auth):
    HA, _ = auth()
    r = client.post("/api/notifications", json={"kind": "email", "target": "soc@acme.com", "min_grade": "C"}, headers=HA)
    assert r.status_code == 201
    cid = r.get_json()["id"]
    assert client.post("/api/notifications", json={"kind": "webhook", "target": "not-a-url"}, headers=HA).status_code == 400
    assert client.post("/api/notifications", json={"kind": "sms", "target": "x"}, headers=HA).status_code == 400
    r = client.patch(f"/api/notifications/{cid}", json={"min_grade": "F"}, headers=HA)
    assert r.get_json()["min_grade"] == "F"
    # SMTP not configured: test send is a logged no-op and reports ok.
    r = client.post(f"/api/notifications/{cid}/test", json={}, headers=HA)
    assert r.status_code == 200 and r.get_json()["ok"] is True
    assert client.delete(f"/api/notifications/{cid}", headers=HA).status_code == 200


def test_health_and_spa(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "ok" and body["engine"] == "simulated"
    assert body["scan_type"] == "connect"
    assert client.get("/").status_code == 200
    assert b"PortWatch" in client.get("/some/deep/link").data
    assert client.get("/js/app.js").status_code == 200


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"
