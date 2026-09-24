"""
Tests for the hardening added during the improvement pass:
  - target guard (SSRF / internal-target protection)
  - authorization approval flow (no self-approval)
  - credential-spray per-run consent and scope enforcement
"""

import importlib
import pytest


# ─────────────────────────── target guard ───────────────────────────

@pytest.fixture
def guard(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    import core.target_guard as tg
    importlib.reload(tg)
    return tg


@pytest.mark.parametrize("target", [
    "127.0.0.1", "localhost", "::1", "0.0.0.0",
    "169.254.169.254", "http://127.0.0.1:8080/admin", "[::1]:8080",
    "10.0.0.5", "192.168.1.10", "172.16.4.4",
])
def test_guard_rejects_dangerous_targets(guard, target):
    with pytest.raises(guard.TargetRejected):
        guard.validate_target(target, resolve=False)


@pytest.mark.parametrize("target", ["example.com", "93.184.216.34", "scanme.nmap.org"])
def test_guard_allows_public_targets(guard, target):
    assert guard.validate_target(target, resolve=False) == target.split("//")[-1]


def test_guard_allows_private_with_flag(monkeypatch):
    monkeypatch.setenv("ALLOW_PRIVATE_TARGETS", "1")
    import core.target_guard as tg
    importlib.reload(tg)
    assert tg.validate_target("10.0.0.5", resolve=False) == "10.0.0.5"
    # loopback and metadata stay blocked even with the flag
    with pytest.raises(tg.TargetRejected):
        tg.validate_target("127.0.0.1", resolve=False)
    with pytest.raises(tg.TargetRejected):
        tg.validate_target("169.254.169.254", resolve=False)


def test_guard_cidr_caps_and_rejects(monkeypatch):
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    import core.target_guard as tg
    importlib.reload(tg)
    # too broad
    with pytest.raises(tg.TargetRejected):
        tg.validate_cidr("10.0.0.0/8")
    # private without flag
    with pytest.raises(tg.TargetRejected):
        tg.validate_cidr("192.168.1.0/28")


# ────────────────── credential-spray safe default ──────────────────

def test_spray_simulates_by_default(monkeypatch):
    monkeypatch.delenv("LIVE_CREDENTIAL_TESTING", raising=False)
    monkeypatch.delenv("PORTWATCH_SIMULATE", raising=False)
    import password_spray
    importlib.reload(password_spray)
    # simulate=False requested, but live is not enabled -> must still simulate
    out = password_spray.spray_http_login("example.com", ["admin"], simulate=False)
    assert out["tool"] == "simulated"


def test_spray_service_refuses_internal_when_live(monkeypatch):
    monkeypatch.setenv("LIVE_CREDENTIAL_TESTING", "1")
    monkeypatch.delenv("PORTWATCH_SIMULATE", raising=False)
    monkeypatch.delenv("ALLOW_PRIVATE_TARGETS", raising=False)
    import core.target_guard as tg
    importlib.reload(tg)
    import password_spray
    importlib.reload(password_spray)
    out = password_spray.spray_http_login("127.0.0.1", ["admin"], simulate=False)
    assert out["tool"] == "refused"
