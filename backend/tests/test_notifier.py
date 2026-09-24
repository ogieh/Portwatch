"""Notification dispatch: thresholds, webhook payload, SMTP path, failure isolation."""

import json

import notifier


class FakeChannel:
    def __init__(self, kind, target, min_grade="C", enabled=True, cid=1):
        self.kind, self.target, self.min_grade, self.enabled, self.id = kind, target, min_grade, enabled, cid


def test_threshold_semantics():
    assert notifier._meets_threshold("F", "C")
    assert notifier._meets_threshold("C", "C")
    assert not notifier._meets_threshold("B", "C")
    assert not notifier._meets_threshold(None, "C")
    assert notifier._meets_threshold("A", "A")


def test_webhook_payload_and_email_noop(app, monkeypatch):
    sent = []

    def fake_urlopen(req, timeout=0):
        sent.append((req.full_url, json.loads(req.data.decode()), req.headers))
    monkeypatch.setattr(notifier.urllib.request, "urlopen", fake_urlopen)
    with app.app_context():
        ok, detail = notifier.send_test(FakeChannel("webhook", "https://hooks.example/x"))
        assert ok and sent[0][0] == "https://hooks.example/x"
        assert "PortWatch" in sent[0][1]["text"] and sent[0][1]["source"] == "PortWatch Pro"
        # No SMTP configured: email is a logged no-op that still reports ok.
        ok, _ = notifier.send_test(FakeChannel("email", "a@b.io"))
        assert ok
        ok, detail = notifier.send_test(FakeChannel("sms", "x"))
        assert not ok and "Unknown" in detail


def test_smtp_path(app, monkeypatch):
    class FakeSMTP:
        sent = []
        def __init__(self, host, port, timeout=0): self.host = host
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): pass
        def login(self, u, p): FakeSMTP.sent.append(("login", u))
        def sendmail(self, frm, to, body): FakeSMTP.sent.append(("mail", frm, to, body))
    monkeypatch.setattr(notifier.smtplib, "SMTP", FakeSMTP)
    app.config.update(SMTP_HOST="smtp.example", SMTP_USER="u", SMTP_PASSWORD="p", SMTP_FROM="pw@example")
    with app.app_context():
        ok, _ = notifier.send_test(FakeChannel("email", "soc@example"))
        assert ok
        assert ("login", "u") in FakeSMTP.sent
        mail = [x for x in FakeSMTP.sent if x[0] == "mail"][0]
        assert mail[2] == ["soc@example"] and "test notification" in mail[3]

        from models.db import User
        u = User(email="r@example", name="R")
        assert notifier.send_password_reset(u, "http://x/#reset/t", 30) is True
        assert any("reset" in x[3] for x in FakeSMTP.sent if x[0] == "mail")


def test_scan_alert_dispatch_and_isolation(app, client, auth, monkeypatch):
    H, _ = auth()
    pid = client.post("/api/projects", json={"name": "P"}, headers=H).get_json()["id"]
    client.post("/api/notifications", json={"kind": "webhook", "target": "https://ok.example/h", "min_grade": "A"}, headers=H)
    client.post("/api/notifications", json={"kind": "webhook", "target": "https://dead.example/h", "min_grade": "A"}, headers=H)
    client.post("/api/notifications", json={"kind": "webhook", "target": "https://quiet.example/h", "min_grade": "F"}, headers=H)
    hits = []

    def fake_urlopen(req, timeout=0):
        if "dead" in req.full_url:
            raise OSError("connection refused")
        hits.append(req.full_url)
    monkeypatch.setattr(notifier.urllib.request, "urlopen", fake_urlopen)

    from conftest import scan_payload
    r = client.post("/api/scan", json=scan_payload(pid, target="10.0.4.22"), headers=H)
    assert r.status_code == 200 and r.get_json()["status"] == "completed"
    grade = r.get_json()["risk"]["grade"]
    assert "https://ok.example/h" in hits
    # The F-only channel fires only for an F.
    assert ("https://quiet.example/h" in hits) == (grade == "F")
    # The failing channel did not break the scan (status completed above).
