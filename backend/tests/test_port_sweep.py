import port_sweep


def test_parse_rustscan():
    assert port_sweep.parse_rustscan("127.0.0.1 -> [22,6379]") == {22, 6379}


def test_parse_naabu():
    assert port_sweep.parse_naabu("host:22\nhost:443\n") == {22, 443}


def test_parse_masscan():
    assert port_sweep.parse_masscan(
        "Discovered open port 6379/tcp on 1.2.3.4") == {6379}


def test_parsers_tolerate_empty():
    assert port_sweep.parse_rustscan("") == set()
    assert port_sweep.parse_naabu("") == set()
    assert port_sweep.parse_masscan("") == set()
    assert port_sweep.parse_rustscan("garbage") == set()


def test_available_sweeper_off(monkeypatch):
    assert port_sweep.available_sweeper("off") is None


def test_sweep_returns_empty_when_tool_missing(monkeypatch):
    monkeypatch.setattr(port_sweep.shutil, "which", lambda n: None)
    assert port_sweep.sweep("127.0.0.1", "1-100", 5) == {}
