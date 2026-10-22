"""The real nmap engine, driven through a fake python-nmap PortScanner.

nmap itself cannot run in CI, but the engine's parsing, phase logic, argument
construction, cancellation and, above all, its output shape (identical to the
simulation's) can all be verified here. A live check against an authorised
host is still documented in docs/DEPLOYMENT.md.
"""

import types

import pytest

import scanner


class FakePortScanner:
    """Records the arguments nmap would have received and replays canned hosts."""
    calls = []
    hosts = {}
    fail_scripts = False

    def __init__(self):
        self._hosts = {}

    def scan(self, target, arguments=""):
        FakePortScanner.calls.append(arguments)
        if "--script" in arguments and FakePortScanner.fail_scripts:
            raise RuntimeError("script phase exploded")
        self._hosts = FakePortScanner.hosts

    def all_hosts(self):
        return list(self._hosts)

    def __getitem__(self, host):
        return self._hosts[host]


class Host(dict):
    def all_protocols(self):
        return list(self.keys())


def _host(with_scripts=False):
    tcp = {
        22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "7.4"},
        80: {"state": "open", "name": "http", "product": "Apache httpd", "version": "2.4.29"},
        443: {"state": "closed", "name": "https", "product": "", "version": ""},
        6379: {"state": "open", "name": "redis", "product": "Redis", "version": "5.0.7"},
    }
    if with_scripts:
        tcp[80]["script"] = {"http-security-headers": "Missing headers: X-Frame-Options",
                             "http-vuln-cve2021-41773": "VULNERABLE: path traversal"}
        tcp[6379]["script"] = {"redis-info": "Redis 5.0.7"}
    return {"10.0.0.9": Host(tcp=tcp)}


@pytest.fixture()
def fake_nmap(monkeypatch):
    fake = types.SimpleNamespace(PortScanner=FakePortScanner, PortScannerError=RuntimeError)
    monkeypatch.setattr(scanner, "nmap", fake)
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")
    FakePortScanner.calls = []
    FakePortScanner.hosts = _host(with_scripts=True)
    FakePortScanner.fail_scripts = False
    return fake


def test_engine_selection(fake_nmap):
    assert scanner.nmap_available()
    assert scanner.run_scan("10.0.0.9", profile="quick")["engine"] == "nmap"
    assert scanner.run_scan("10.0.0.9", profile="quick", simulate=True)["engine"] == "simulated"


def test_real_scan_shape_matches_simulation(fake_nmap):
    real = scanner.run_scan("10.0.0.9", profile="standard")
    sim = scanner.run_scan("10.0.0.9", profile="standard", simulate=True)
    assert set(real) == set(sim)
    assert set(real["ports"][0]) == set(sim["ports"][0])
    assert real["resolved_host"] == "10.0.0.9"
    assert real["credential_checks"] is None
    ports = {p["port"]: p for p in real["ports"]}
    assert ports[22]["version"] == "OpenSSH 7.4" and ports[22]["risk"] == "medium"
    assert ports[443]["state"] == "closed" and ports[443]["version"] == "https"
    assert ports[6379]["risk"] == "high"
    assert "VULNERABLE" in ports[80]["scripts"]["http-vuln-cve2021-41773"]
    assert "Vulnerability scripts flagged" in real["summary"]


def test_downstream_layers_accept_real_output(fake_nmap):
    import scoring, compliance, cve_intel
    real = scanner.run_scan("10.0.0.9", profile="standard")
    risk = scoring.compute_risk(real["ports"], None)
    assert risk["grade"] in "ABCDF" and risk["breakdown"]
    assert isinstance(compliance.generate_compliance_tags(real["ports"], None), list)
    intel = cve_intel.enrich(real["ports"], None)
    assert any(f["confidence"] == "confirmed" for f in intel)
    assert any("CVE-2022-0543" in f["cve"] for f in intel)


def test_arguments_scan_type_and_phases(fake_nmap):
    scanner.run_scan("10.0.0.9", profile="standard", scan_type="connect")
    assert FakePortScanner.calls[0].startswith("-sT -sV -T4 -Pn --top-ports 100")
    # Phase 2 web scripts on open web ports only (80), phase 3 DB scripts on 6379.
    assert any("-p 80 --script" in c for c in FakePortScanner.calls)
    assert any("-p 6379 --script redis-info" in c for c in FakePortScanner.calls)
    assert all(c.startswith("-sT") for c in FakePortScanner.calls)

    FakePortScanner.calls = []
    scanner.run_scan("10.0.0.9", profile="quick", scan_type="syn")
    assert FakePortScanner.calls == ["-sS -sV -T4 -Pn --top-ports 20 --host-timeout 60s"]

    with pytest.raises(ValueError):
        scanner.run_scan("10.0.0.9", scan_type="xmas")


def test_script_phase_failure_keeps_phase1_results(fake_nmap):
    FakePortScanner.fail_scripts = True
    real = scanner.run_scan("10.0.0.9", profile="deep")
    assert len(real["ports"]) == 4
    assert all(p["scripts"] == {} for p in real["ports"])


def test_credential_scripts_only_when_opted_in(fake_nmap, monkeypatch):
    monkeypatch.setattr(scanner.authtest, "run_credential_checks",
                        lambda host, ports: {"enabled": True, "http_login_findings": [], "db_findings": []})
    FakePortScanner.hosts = {"h": Host(tcp={3306: {"state": "open", "name": "mysql", "product": "MySQL", "version": "5.7"}})}
    scanner.run_scan("h", profile="standard", credential_checks=False)
    assert not any("mysql-brute" in c for c in FakePortScanner.calls)
    FakePortScanner.calls = []
    out = scanner.run_scan("h", profile="standard", credential_checks=True)
    assert any("mysql-brute" in c for c in FakePortScanner.calls)
    assert out["credential_checks"]["enabled"] is True


def test_credential_check_crash_is_reported_not_raised(fake_nmap, monkeypatch):
    def boom(host, ports):
        raise RuntimeError("socket blew up")
    monkeypatch.setattr(scanner.authtest, "run_credential_checks", boom)
    out = scanner.run_scan("10.0.0.9", profile="quick", credential_checks=True)
    assert "socket blew up" in out["credential_checks"]["error"]


def test_unreachable_host_raises(fake_nmap):
    FakePortScanner.hosts = {}
    with pytest.raises(RuntimeError, match="could not get any response"):
        scanner.run_scan("10.0.0.9", profile="quick")


def test_cancel_between_phases(fake_nmap):
    flags = iter([True])
    with pytest.raises(scanner.ScanCancelled):
        scanner.run_scan("10.0.0.9", profile="standard", cancel_check=lambda: next(flags, False))
    # Only phase 1 ran.
    assert len(FakePortScanner.calls) == 1


def test_nmap_missing_raises_clear_error(monkeypatch):
    monkeypatch.setattr(scanner, "nmap", None)
    with pytest.raises(RuntimeError, match="nmap executable not found"):
        scanner._check_nmap_available()
    assert scanner.run_scan("x", profile="quick")["engine"] == "simulated"
