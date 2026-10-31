"""Independent port oracle for the differential harness.

The whole point of differential validation is to judge PortWatch against a
witness that shares NONE of its code. PortWatch's real engine is python-nmap;
this module is a plain-socket TCP connect prober plus optional adapters for a
second, external scanner (RustScan / naabu / masscan). Neither path imports
nmap or anything from backend/services, so agreement between them and PortWatch
is real evidence, not a tautology.

Two oracles, used together by the harness:
  * probe_ports()  - always available, no root, no install. The baseline witness.
  * external_scan() - used when a real second scanner is on PATH, for a second
                      independent opinion. Returns None when none is installed.
"""

import shutil
import socket
import subprocess
import re


def probe_ports(host, ports, timeout=1.0):
    """Return the set of TCP ports on `host` that accept a connection.

    A pure socket connect() scan: if the three-way handshake completes the port
    is open. This is independent of nmap and of PortWatch entirely.
    """
    open_ports = set()
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, int(port))) == 0:
                open_ports.add(int(port))
        except OSError:
            pass
        finally:
            sock.close()
    return open_ports


def banner_grab(host, port, timeout=1.5, send=b"\r\n"):
    """Best-effort banner for sanity-checking service identity. Independent of
    nmap's -sV. Returns a short decoded string or ''."""
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(256)
                if not data:
                    s.sendall(send)
                    data = s.recv(256)
            except OSError:
                data = b""
            return data.decode("latin-1", "replace").strip()
    except OSError:
        return ""


# ───────────────────────── EXTERNAL SECOND SCANNER ─────────────────────────
# If a real second scanner is installed we use it as a second independent
# opinion. Each adapter parses that tool's own output into a set of open ports.
# Order of preference: rustscan, naabu, masscan.

def available_external_scanner():
    for name in ("rustscan", "naabu", "masscan"):
        if shutil.which(name):
            return name
    return None


def external_scan(host, ports, timeout=60):
    """Run whichever external scanner is installed over the given candidate
    ports and return the open set, or None if no external scanner is available.
    """
    tool = available_external_scanner()
    if tool is None:
        return None
    port_csv = ",".join(str(p) for p in sorted(set(int(p) for p in ports)))
    try:
        if tool == "rustscan":
            out = subprocess.run(
                ["rustscan", "-a", host, "-p", port_csv, "--greppable",
                 "--no-config"],
                capture_output=True, text=True, timeout=timeout,
            ).stdout
            return _parse_rustscan(out)
        if tool == "naabu":
            out = subprocess.run(
                ["naabu", "-host", host, "-p", port_csv, "-silent"],
                capture_output=True, text=True, timeout=timeout,
            ).stdout
            return _parse_hostport_lines(out)
        if tool == "masscan":
            out = subprocess.run(
                ["masscan", host, "-p", port_csv, "--rate", "1000"],
                capture_output=True, text=True, timeout=timeout,
            ).stdout
            return _parse_masscan(out)
    except (subprocess.SubprocessError, OSError):
        return None
    return None


def _parse_rustscan(text):
    # Greppable lines look like: 127.0.0.13 -> [6379]
    found = set()
    for m in re.finditer(r"->\s*\[([0-9,\s]+)\]", text):
        for p in m.group(1).split(","):
            p = p.strip()
            if p.isdigit():
                found.add(int(p))
    return found


def _parse_hostport_lines(text):
    # naabu -silent prints host:port per line.
    found = set()
    for line in text.splitlines():
        m = re.search(r":(\d+)\s*$", line.strip())
        if m:
            found.add(int(m.group(1)))
    return found


def _parse_masscan(text):
    # masscan stdout: "Discovered open port 6379/tcp on 127.0.0.13"
    found = set()
    for m in re.finditer(r"open port (\d+)/tcp", text):
        found.add(int(m.group(1)))
    return found
