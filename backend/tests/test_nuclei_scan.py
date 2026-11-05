import nuclei_scan


def test_parse_jsonl_extracts_fields():
    line = ('{"template-id":"apache-cve-2021-41773","info":{"name":"Path Traversal",'
            '"severity":"critical","reference":["CVE-2021-41773"]},'
            '"matched-at":"http://h/cgi-bin/"}')
    out = nuclei_scan.parse_jsonl(line)
    assert out[0]["template_id"] == "apache-cve-2021-41773"
    assert out[0]["severity"] == "critical"


def test_parse_jsonl_skips_malformed_lines():
    out = nuclei_scan.parse_jsonl("not json\n" + '{"template-id":"x","info":{"severity":"low"}}')
    assert len(out) == 1


def test_run_nuclei_noop_when_unavailable(monkeypatch):
    monkeypatch.setattr(nuclei_scan, "nuclei_available", lambda: False)
    r = nuclei_scan.run_nuclei("h", [80], simulate=False)
    assert r["enabled"] is False and r["findings"] == []


def test_simulate_nuclei_is_deterministic():
    assert nuclei_scan.simulate_nuclei("t", [80]) == nuclei_scan.simulate_nuclei("t", [80])


def test_nuclei_per_request_timeout_is_fixed(monkeypatch):
    import subprocess
    import nuclei_scan
    seen = {}
    monkeypatch.setattr(nuclei_scan, "nuclei_available", lambda: True)

    def fake(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
    monkeypatch.setattr(nuclei_scan.subprocess, "run", fake)
    nuclei_scan.run_nuclei("h", [80], timeout=300)
    assert seen["cmd"][seen["cmd"].index("-timeout") + 1] == "10"
    assert seen["kw"]["timeout"] == 300
