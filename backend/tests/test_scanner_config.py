import scanner
from core.config import Config


def test_profiles_have_sweep_range():
    for p in ("quick", "standard", "deep"):
        assert "sweep_range" in scanner.SCAN_PROFILES[p]
    assert scanner.SCAN_PROFILES["quick"]["sweep_range"] == "--top-ports 100"
    assert scanner.SCAN_PROFILES["standard"]["sweep_range"] == "--top-ports 1000"
    assert scanner.SCAN_PROFILES["deep"]["sweep_range"] == "-p-"


def test_config_defaults():
    assert Config.PORT_SWEEPER == "auto"
    assert Config.NUCLEI_ENABLED == "auto"
    assert Config.NUCLEI_MIN_SEVERITY == "low"
    assert isinstance(Config.NUCLEI_TIMEOUT, int)


def test_protocol_level_nse_scripts():
    assert "ssl-poodle" in scanner.NSE_SCRIPTS.split(",")
    assert scanner.PROTOCOL_SCRIPTS == {
        21: "ftp-anon", 445: "smb-os-discovery,smb-vuln-ms17-010"}


def test_ms17_010_maps_to_cve():
    import cve_intel
    rec = cve_intel.NSE_CVE_MAP["smb-vuln-ms17-010"]
    assert rec["cve"] == ["CVE-2017-0143"] and rec["severity"] == "high"
