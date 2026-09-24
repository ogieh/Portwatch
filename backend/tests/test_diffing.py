"""Unit tests for scan comparison."""

import pytest

import diffing


def scan(target, ports, score=None, grade=None, profile="standard", sid=1):
    return {"id": sid, "target": target, "profile": profile, "ports": ports,
            "risk": {"score": score, "grade": grade}, "timestamp": "2026-01-01T00:00:00"}


def p(number, state="open", service="http", version="nginx 1.18.0", risk="low"):
    return {"port": number, "state": state, "service": service, "version": version, "risk": risk}


@pytest.mark.parametrize("raw,norm", [
    ("Example.com", "example.com"),
    ("http://example.com/", "example.com"),
    ("HTTPS://Example.com/path?x=1#f", "example.com"),
    ("  10.0.0.1  ", "10.0.0.1"),
    (None, ""),
])
def test_normalize_target(raw, norm):
    assert diffing.normalize_target(raw) == norm


def test_different_targets_rejected():
    with pytest.raises(ValueError):
        diffing.build_diff(scan("a.com", []), scan("b.com", []))


def test_same_target_different_spelling_is_ok():
    d = diffing.build_diff(scan("http://A.com/", []), scan("a.com", []))
    assert d["opened_ports"] == [] and d["closed_ports"] == []


def test_opened_closed_changed():
    before = scan("t", [p(22, service="ssh", version="OpenSSH 7.4"), p(80), p(443, state="closed"),
                        p(3306, risk="high")], score=70, grade="C", sid=1)
    after = scan("t", [p(22, service="ssh", version="OpenSSH 9.6"), p(80, state="filtered"),
                       p(443), p(3306, risk="high")], score=85, grade="B", sid=2)
    d = diffing.build_diff(before, after)
    assert [x["port"] for x in d["opened_ports"]] == [443]
    assert [x["port"] for x in d["closed_ports"]] == [80]
    assert d["changed_ports"] == [{"port": 22, "from": {"service": "ssh", "version": "OpenSSH 7.4"},
                                   "to": {"service": "ssh", "version": "OpenSSH 9.6"},
                                   "version_changed": True}]
    assert d["score_delta"] == 15
    assert d["grade_change"] == {"from": "C", "to": "B"}
    assert d["profile_mismatch"] is False
    assert d["before"]["id"] == 1 and d["after"]["id"] == 2


def test_profile_mismatch_and_missing_scores():
    d = diffing.build_diff(scan("t", [], profile="quick"), scan("t", [], profile="deep"))
    assert d["profile_mismatch"] is True
    assert d["score_delta"] is None and d["grade_change"] is None


def test_no_grade_change_when_same_grade():
    d = diffing.build_diff(scan("t", [], score=90, grade="A"), scan("t", [], score=95, grade="A"))
    assert d["score_delta"] == 5 and d["grade_change"] is None
