"""Fast port-sweep discovery (rustscan / naabu / masscan).

Runs an external sweeper to find candidate open ports quickly; results are fed
into the nmap scan. A missing tool is never an error: callers get None/{}.

NOTE: the parsers here are an intentional, independent copy of the logic in
tests/differential/independent_scanner.py. Do not unify them; that harness
must stay independent of production code.
"""

import re
import shutil
import subprocess

from core.config import Config

SWEEPERS = ("rustscan", "naabu", "masscan")


def parse_rustscan(text):
    found = set()
    for m in re.finditer(r"->\s*\[([0-9,\s]+)\]", text or ""):
        for p in m.group(1).split(","):
            p = p.strip()
            if p.isdigit():
                found.add(int(p))
    return found


def parse_naabu(text):
    found = set()
    for line in (text or "").splitlines():
        m = re.search(r":(\d+)\s*$", line.strip())
        if m:
            found.add(int(m.group(1)))
    return found


def parse_masscan(text):
    return {int(m.group(1))
            for m in re.finditer(r"open port (\d+)/tcp", text or "")}


_PARSERS = {
    "rustscan": parse_rustscan,
    "naabu": parse_naabu,
    "masscan": parse_masscan,
}


def available_sweeper(preference=None):
    """Return the sweeper name to use, or None. preference: auto/off/<tool>."""
    if preference is None:
        preference = getattr(Config, "PORT_SWEEPER", "auto")
    preference = (preference or "auto").strip().lower()
    if preference in ("off", "none", "disabled", "0", "false"):
        return None
    if preference in SWEEPERS:
        return preference if shutil.which(preference) else None
    for name in SWEEPERS:
        if shutil.which(name):
            return name
    return None


def _command(tool, target, port_spec):
    """Build argv; port_spec is a neutral range ("1-65535") or comma list."""
    spec = str(port_spec).strip()
    if tool == "rustscan":
        # rustscan's -r takes a single start-end range; -p takes a list
        flag = "-r" if re.fullmatch(r"\d+-\d+", spec) else "-p"
        return ["rustscan", "-a", target, flag, spec, "--greppable",
                "--no-config"]
    if tool == "naabu":
        return ["naabu", "-host", target, "-p", spec, "-silent"]
    return ["masscan", target, "-p", spec, "--rate", "1000"]


def sweep(target, port_spec, timeout, cancel_check=None):
    """Return {open_port: {tool_name}}; {} if no tool, failure, or cancelled."""
    tool = available_sweeper()
    if tool is None:
        return {}
    if cancel_check is not None and cancel_check():
        return {}
    try:
        out = subprocess.run(
            _command(tool, target, str(port_spec)),
            capture_output=True, text=True, timeout=timeout,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return {}
    return {p: {tool} for p in _PARSERS[tool](out)}
