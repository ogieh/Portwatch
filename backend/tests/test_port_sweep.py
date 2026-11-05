import re
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


def test_sweep_commands_from_real_profiles_have_no_nmap_isms():
    from services import scanner
    for prof, cfg in scanner.SCAN_PROFILES.items():
        for tool in port_sweep.SWEEPERS:
            argv = port_sweep._command(tool, "10.0.0.1", cfg["sweep_range"])
            joined = " ".join(argv)
            assert "--top-ports" not in joined
            assert "-p-" not in argv
            assert cfg["sweep_range"] in argv
            assert re.fullmatch(r"\d+-\d+", cfg["sweep_range"])


def test_rustscan_uses_range_flag():
    argv = port_sweep._command("rustscan", "h", "1-65535")
    assert argv[argv.index("-r") + 1] == "1-65535"
    assert "-p" not in argv and "--greppable" in argv and "--no-config" in argv
    assert "-p" in port_sweep._command("rustscan", "h", "22,80")
    assert port_sweep._command("naabu", "h", "1-100")[3:5] == ["-p", "1-100"]
    assert port_sweep._command("masscan", "h", "1-100")[2:4] == ["-p", "1-100"]
