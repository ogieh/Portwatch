import types

import port_sweep
import scanner
from test_real_engine import FakePortScanner, _host


def test_ports_carry_confidence_fields():
    r = scanner.run_scan("sim-host", profile="standard", simulate=True)
    for p in r["ports"]:
        assert "seen_by" in p and p["confidence"] in ("confirmed", "single-engine")


def test_result_has_nuclei_list():
    r = scanner.run_scan("sim-host", profile="standard", simulate=True)
    assert isinstance(r["nuclei"], list)


def test_backward_compatible_keys_present():
    r = scanner.run_scan("sim-host", profile="quick", simulate=True)
    assert set(["target", "profile", "credential_checks", "resolved_host",
                "ports", "summary", "engine"]).issubset(r)
    for p in r["ports"]:
        assert set(["port", "state", "service", "version", "risk", "scripts"]).issubset(p)


def _fake_nmap(monkeypatch):
    fake = types.SimpleNamespace(PortScanner=FakePortScanner, PortScannerError=RuntimeError)
    monkeypatch.setattr(scanner, "nmap", fake)
    monkeypatch.setattr(scanner.shutil, "which", lambda name: "/usr/bin/nmap")
    FakePortScanner.calls = []
    FakePortScanner.hosts = _host()
    FakePortScanner.fail_scripts = False


def test_discovery_merges_sweeper_only_port(monkeypatch):
    _fake_nmap(monkeypatch)
    monkeypatch.setattr(port_sweep, "available_sweeper", lambda preference=None: "rustscan")
    monkeypatch.setattr(port_sweep, "sweep",
                        lambda t, spec, timeout, cancel_check=None:
                        {22: {"rustscan", "naabu"}, 9999: {"rustscan"}})
    r = scanner.run_scan("10.0.0.9", profile="quick", simulate=False)
    by = {p["port"]: p for p in r["ports"]}
    assert by[9999]["seen_by"] == ["rustscan"]
    assert by[9999]["confidence"] == "single-engine"
    assert by[9999]["service"] == "unknown"
    assert by[22]["seen_by"] == ["naabu", "nmap", "rustscan"]
    assert by[22]["confidence"] == "confirmed"
    assert "-p 22,9999" in FakePortScanner.calls[0]
    assert "--top-ports" not in FakePortScanner.calls[0]


def test_no_sweeper_keeps_top_ports_phase(monkeypatch):
    _fake_nmap(monkeypatch)
    monkeypatch.setattr(port_sweep, "available_sweeper", lambda preference=None: None)
    r = scanner.run_scan("10.0.0.9", profile="quick", simulate=False)
    assert FakePortScanner.calls[0] == "-sT -sV -T4 -Pn --top-ports 20 --host-timeout 60s"
    assert all(p["seen_by"] == ["nmap"] and p["confidence"] == "single-engine"
               for p in r["ports"])
    assert isinstance(r["nuclei"], list)
