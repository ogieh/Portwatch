"""Unit tests for the offline CVE knowledge layer: every version regex must
match its intended banner and nothing adjacent."""

import pytest

import cve_intel


def port(number, service, version, state="open", scripts=None):
    return {"port": number, "state": state, "service": service, "version": version,
            "risk": "low", "scripts": scripts or {}}


@pytest.mark.parametrize("banner,cve", [
    ("vsftpd 2.3.4", "CVE-2011-2523"),
    ("OpenSSH 7.4", "CVE-2016-10009"),
    ("OpenSSH 7.0p1", "CVE-2016-10009"),
    ("Apache httpd 2.4.29", "CVE-2021-40438"),
    ("Apache httpd 2.4.48", "CVE-2021-40438"),
    ("nginx 1.18.0", "CVE-2021-23017"),
    ("nginx 1.20.1", "CVE-2021-23017"),
    ("MySQL 5.7.38", "CVE-2016-6662"),
    ("MariaDB 5.5.1", "CVE-2016-6662"),
    ("Redis 5.0.7", "CVE-2022-0543"),
    ("Redis 4.0.9", "CVE-2022-0543"),
    ("Exim 4.91", "CVE-2019-10149"),
    ("ProFTPD 1.3.5", "CVE-2015-3306"),
])
def test_version_regex_matches_vulnerable_banner(banner, cve):
    findings = cve_intel.enrich([port(9999, "svc", banner)])
    cves = {c for f in findings for c in f["cve"]}
    assert cve in cves, findings
    likely = [f for f in findings if f["confidence"] == "likely"]
    assert likely and likely[0]["remediation"]


@pytest.mark.parametrize("banner", [
    "vsftpd 3.0.3", "OpenSSH 8.9p1", "OpenSSH 9.6p1", "Apache httpd 2.4.52",
    "Apache httpd 2.4.51", "nginx 1.25.3", "nginx 1.21.0", "MySQL 8.0.33",
    "Redis 7.0.11", "Redis 6.2.0", "Exim 4.94", "ProFTPD 1.3.6", "Pure-FTPd",
])
def test_version_regex_does_not_match_patched_banner(banner):
    findings = cve_intel.enrich([port(9999, "svc", banner)])
    assert all(f["confidence"] != "likely" for f in findings), findings


def test_nse_confirmed_finding():
    p = port(80, "http", "Apache httpd 2.4.49",
             scripts={"http-vuln-cve2021-41773": "VULNERABLE:\n  path traversal"})
    findings = cve_intel.enrich([p])
    confirmed = [f for f in findings if f["confidence"] == "confirmed"]
    assert len(confirmed) == 1
    assert confirmed[0]["cve"] == ["CVE-2021-41773"] and confirmed[0]["severity"] == "critical"
    # Same script without VULNERABLE is not asserted.
    p["scripts"] = {"http-vuln-cve2021-41773": "Couldn't find a match"}
    assert not [f for f in cve_intel.enrich([p]) if f["confidence"] == "confirmed"]


def test_exposure_guidance_and_ordering():
    ports = [port(6379, "redis", "Redis 7.0.11"), port(25, "smtp", "Postfix smtpd"),
             port(23, "telnet", "Linux telnetd"), port(80, "http", "nginx 1.25.3")]
    findings = cve_intel.enrich(ports)
    sev = [f["severity"] for f in findings]
    assert sev == sorted(sev, key=lambda s: cve_intel.SEV_RANK[s])
    assert findings[0]["port"] == 6379 and findings[0]["severity"] == "critical"
    assert all(f["confidence"] == "informational" for f in findings)


def test_closed_ports_are_ignored_and_dedup():
    closed = port(6379, "redis", "Redis 5.0.7", state="closed")
    assert cve_intel.enrich([closed]) == []
    dup = [port(21, "ftp", "vsftpd 2.3.4"), port(21, "ftp", "vsftpd 2.3.4")]
    findings = cve_intel.enrich(dup)
    keys = [(f["port"], f["title"]) for f in findings]
    assert len(keys) == len(set(keys))


def test_summarize():
    ports = [port(21, "ftp", "vsftpd 2.3.4"), port(23, "telnet", "Linux telnetd")]
    s = cve_intel.summarize(cve_intel.enrich(ports))
    assert s["total"] == 3
    assert s["unique_cves"] == ["CVE-2011-2523"]
    assert s["counts"]["critical"] == 1 and s["counts"]["high"] == 1 and s["counts"]["medium"] == 1
    assert s["confirmed"] == 0
    assert cve_intel.summarize([]) == {"total": 0, "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                                       "unique_cves": [], "confirmed": 0}
