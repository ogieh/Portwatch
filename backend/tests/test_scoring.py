"""Unit tests for the preserved risk-scoring model (boundaries and caps)."""

import pytest

import scoring


def port(number, state="open", risk="low", scripts=None, service="http", version=""):
    return {"port": number, "state": state, "service": service, "version": version,
            "risk": risk, "scripts": scripts or {}}


@pytest.mark.parametrize("score,grade", [
    (100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"),
    (59, "D"), (40, "D"), (39, "F"), (0, "F"),
])
def test_grade_boundaries(score, grade):
    assert scoring.grade_for_score(score) == grade


def test_clean_scan_is_perfect():
    r = scoring.compute_risk([port(80, state="closed"), port(443, state="filtered")])
    assert r == {"score": 100, "grade": "A", "breakdown": []}


def test_port_weights():
    # Per-service criticality: 23 (Telnet) 20, 22 (SSH) 6, 80/8080 (web) 3 each.
    ports = [port(23), port(22), port(80), port(8080)]
    r = scoring.compute_risk(ports)
    assert r["score"] == 100 - 20 - 6 - 3 - 3
    reasons = [b["reason"] for b in r["breakdown"]]
    assert "1 critical-exposure service(s) open (ports: 23)" in reasons
    assert "1 elevated-exposure service(s) open (ports: 22)" in reasons
    assert "2 standard-exposure service(s) open (ports: 80, 8080)" in reasons


def test_vuln_script_cap():
    scripts = {"http-vuln-cve2021-41773": "VULNERABLE: x", "http-vuln-cve2017-5638": "VULNERABLE: y"}
    ports = [port(80, scripts=scripts), port(8080, scripts=scripts), port(8443, scripts=scripts)]
    r = scoring.compute_risk(ports)
    # 6 hits * 20 = 120, capped at 40; plus web ports 80(3) + 8080(3) + 8443(2) = 8.
    assert r["score"] == 100 - 40 - 8
    assert any(b["points"] == -40 for b in r["breakdown"])


def test_vuln_script_requires_vulnerable_keyword():
    ports = [port(80, scripts={"http-vuln-cve2021-41773": "NOT VULNERABLE"})]
    # Contains the substring VULNERABLE, so the (conservative) engine counts it.
    # Port 80 criticality is 3.
    assert scoring.compute_risk(ports)["score"] == 100 - 3 - 20
    ports = [port(80, scripts={"http-vuln-cve2021-41773": "Couldn't find a match"})]
    assert scoring.compute_risk(ports)["score"] == 97


def test_header_cipher_method_penalties_and_caps():
    scripts = {
        "ssl-enum-ciphers": "TLS_RSA_WITH_RC4_128_SHA - weak",
        "ssl-dh-params": "VULNERABLE: Logjam",
        "http-security-headers": "Missing headers: Content-Security-Policy, X-Frame-Options, "
                                 "Strict-Transport-Security, Referrer-Policy, Permissions-Policy",
        "http-methods": "Supported Methods: GET POST TRACE",
    }
    r = scoring.compute_risk([port(443, scripts=scripts)])
    # 443 criticality 2 + cipher 10 + dh 5 + headers min(5*3, 12)=12 + methods 6
    assert r["score"] == 100 - 2 - 10 - 5 - 12 - 6
    three = [port(443, scripts=scripts), port(8443, scripts=scripts), port(80, scripts=scripts)]
    r = scoring.compute_risk(three)
    # caps: cipher 20, dh 10, headers 12, methods 12; ports 443(2)+8443(2)+80(3)=7
    assert r["score"] == 100 - 7 - 20 - 10 - 12 - 12


def test_credential_check_deductions():
    cc = {
        "http_login_findings": [{"verdict": "none_observed"}, {"verdict": "throttled"},
                                {"verdict": "none_observed"}, {"verdict": "none_observed"}],
        "db_findings": [{"vulnerable": True}, {"vulnerable": False}, {"vulnerable": True},
                        {"vulnerable": True}],
    }
    r = scoring.compute_risk([port(80)], cc)
    # port 80 criticality 3; 3 unprotected logins * 12 = 36 capped 24;
    # 3 db failures * 20 = 60 capped 40
    assert r["score"] == 100 - 3 - 24 - 40
    assert r["grade"] == "F"


def test_score_floor_is_zero():
    ports = [port(p, risk="high") for p in (21, 23, 3306, 3389, 5432, 6379, 27017)]
    cc = {"http_login_findings": [{"verdict": "none_observed"}] * 5,
          "db_findings": [{"vulnerable": True}] * 5}
    r = scoring.compute_risk(ports, cc)
    assert r["score"] == 0 and r["grade"] == "F"


def test_non_string_script_output_is_ignored():
    ports = [port(80, scripts={"http-vuln-cve2021-41773": {"weird": "VULNERABLE"}})]
    # Port 80 criticality 3; the non-string script output is not counted.
    assert scoring.compute_risk(ports)["score"] == 97


def test_nuclei_findings_deduct_points():
    base = scoring.compute_risk([], None)["score"]
    with_f = scoring.compute_risk([], None, nuclei=[{"severity": "critical"}])["score"]
    assert with_f < base


def test_nuclei_penalty_capped_and_nonnegative():
    many = [{"severity": "critical"}] * 20
    r = scoring.compute_risk([], None, nuclei=many)
    assert r["score"] >= 0
    cap_line = [b for b in r["breakdown"] if "nuclei" in b["reason"].lower()][0]
    assert -cap_line["points"] <= scoring.NUCLEI_PENALTY_CAP


def test_nuclei_none_or_empty_adds_no_line():
    base = scoring.compute_risk([], None)
    for n in (None, [], [{"severity": "info"}]):
        r = scoring.compute_risk([], None, nuclei=n)
        assert r == base
