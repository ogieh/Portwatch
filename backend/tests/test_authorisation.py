"""The authorisation-to-scan gate and per-project allowlists."""

from conftest import scan_payload


def test_scan_requires_consent(client, project):
    H, _, proj = project
    payload = scan_payload(proj["id"])
    payload["authorised"] = False
    r = client.post("/api/scan", json=payload, headers=H)
    assert r.status_code == 403
    assert "authorised" in r.get_json()["error"]
    del payload["authorised"]
    assert client.post("/api/scan", json=payload, headers=H).status_code == 403
    assert client.get("/api/scans", headers=H).get_json() == []


def test_schedule_requires_consent(client, project):
    H, _, proj = project
    r = client.post("/api/schedules", json={"project_id": proj["id"], "target": "a.example",
                                            "interval_hours": 6}, headers=H)
    assert r.status_code == 403


def test_project_allowlist_enforced(client, project):
    H, _, proj = project
    pid = proj["id"]
    r = client.patch(f"/api/projects/{pid}",
                     json={"allowed_targets": "scanme.example\n*.acme.com, 10.0.0.5"}, headers=H)
    assert r.status_code == 200
    assert r.get_json()["allowed_targets"] == ["scanme.example", "*.acme.com", "10.0.0.5"]

    assert client.post("/api/scan", json=scan_payload(pid, target="evil.example"), headers=H).status_code == 403
    assert client.post("/api/scan", json=scan_payload(pid, target="scanme.example"), headers=H).status_code == 200
    assert client.post("/api/scan", json=scan_payload(pid, target="api.acme.com"), headers=H).status_code == 200
    assert client.post("/api/scan", json=scan_payload(pid, target="acme.com"), headers=H).status_code == 200
    assert client.post("/api/scan", json=scan_payload(pid, target="https://10.0.0.5/login"), headers=H).status_code == 200
    assert client.post("/api/scan", json=scan_payload(pid, target="10.0.0.50"), headers=H).status_code == 403
    # Schedules honour the same list.
    r = client.post("/api/schedules", json={"project_id": pid, "target": "other.example",
                                            "interval_hours": 6, "authorised": True}, headers=H)
    assert r.status_code == 403
    # Clearing the allowlist re-opens the project (consent still required).
    client.patch(f"/api/projects/{pid}", json={"allowed_targets": []}, headers=H)
    assert client.post("/api/scan", json=scan_payload(pid, target="evil.example"), headers=H).status_code == 200


def test_allowlist_validation(client, project):
    H, _, proj = project
    assert client.patch(f"/api/projects/{proj['id']}", json={"allowed_targets": "bad host"}, headers=H).status_code == 400
    assert client.patch(f"/api/projects/{proj['id']}", json={"allowed_targets": 42}, headers=H).status_code == 400
    r = client.post("/api/projects", json={"name": "P2", "allowed_targets": ["A.Example", "a.example"]}, headers=H)
    assert r.status_code == 201 and r.get_json()["allowed_targets"] == ["a.example"]


def test_target_must_be_single_host(client, project):
    H, _, proj = project
    assert client.post("/api/scan", json=scan_payload(proj["id"], target="a b"), headers=H).status_code == 400
    assert client.post("/api/scan", json=scan_payload(proj["id"], target="x" * 300), headers=H).status_code == 400


def test_target_allowed_model_logic(app):
    from models.db import Project
    p = Project(name="x", allowed_targets="*.example.com\nhost.local")
    assert p.target_allowed("api.example.com")
    assert p.target_allowed("example.com")
    assert p.target_allowed("HOST.LOCAL")
    assert not p.target_allowed("notexample.com")
    assert not p.target_allowed("host.local.evil")
    assert Project(name="y", allowed_targets="").target_allowed("anything")
