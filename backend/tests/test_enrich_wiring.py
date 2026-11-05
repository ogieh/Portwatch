from services import scan_service


def test_enrich_passes_nuclei_to_risk_and_intel():
    scan_result = {
        "ports": [{"port": 80, "state": "open", "service": "http", "banner": "", "version": ""}],
        "credential_checks": None,
        "nuclei": [{
            "template_id": "CVE-2021-41773", "name": "Apache path traversal",
            "severity": "critical", "port": 80, "matched_at": "http://x:80/",
            "cve": ["CVE-2021-41773"],
        }],
    }
    baseline = dict(scan_result, nuclei=[])
    out = scan_service._enrich(scan_result)
    base = scan_service._enrich(baseline)
    assert "nuclei finding" in str(out["risk"]["breakdown"])
    assert "nuclei finding" not in str(base["risk"]["breakdown"])
    assert any(i.get("confidence") == "confirmed" for i in out["intel"])
