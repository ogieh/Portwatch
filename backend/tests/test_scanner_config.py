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
