"""
Network enumeration service for PortWatch Pro.

Active enumeration of non-web services:
  1. SMB share enumeration (enum4linux / smbclient)
  2. SNMP community string testing (snmpwalk)
  3. NFS export listing (showmount)
  4. Virtual host discovery (Host header fuzzing)
  5. OS fingerprinting (nmap -O)
  6. Banner grabbing (raw socket connection)

All functions have simulation fallback.
"""

import hashlib
import os
import random
import re
import shutil
import socket
import subprocess

SIMULATE = os.environ.get("PORTWATCH_SIMULATE", "").lower() in ("1", "true", "yes")

def _seeded_rng(target):
    seed = int(hashlib.sha256(target.encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)

def _tool_available(name):
    return shutil.which(name) is not None

def _run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "", "", -1


# ============================================================
# 1. SMB ENUMERATION
# ============================================================

def enumerate_smb(target, simulate=None):
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_smb(target)

    if _tool_available("enum4linux"):
        out, _, rc = _run(["enum4linux", "-a", target], timeout=60)
        if rc == 0 and out:
            shares = re.findall(r'\|\s*([\w$]+)\s*\|.*\|', out)
            users = re.findall(r'user:\[(\w+)\]', out)
            os_info = re.search(r'OS:\s*\[([^\]]+)\]', out)
            return {
                "target": target, "shares": shares, "users": users,
                "os": os_info.group(1) if os_info else "",
                "raw": out[:2000], "tool": "enum4linux",
            }

    if _tool_available("smbclient"):
        out, _, rc = _run(["smbclient", "-L", target, "-N"], timeout=15)
        if rc == 0:
            shares = re.findall(r'\s+([\w$]+)\s+Disk', out)
            return {"target": target, "shares": shares, "users": [], "os": "", "raw": out[:1000], "tool": "smbclient"}

    return {"target": target, "shares": [], "users": [], "os": "", "raw": "", "tool": "unavailable"}


def _sim_smb(target):
    rng = _seeded_rng(target)
    shares = rng.sample(["IPC$", "ADMIN$", "C$", "shared", "public", "backups", "finance"], rng.randint(2, 5))
    users = rng.sample(["administrator", "guest", "svc_backup", "jsmith", "admin"], rng.randint(1, 3))
    return {"target": target, "shares": shares, "users": users, "os": "Windows Server 2019", "raw": "(simulated)", "tool": "simulated"}


# ============================================================
# 2. SNMP
# ============================================================

def test_snmp(target, simulate=None):
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_snmp(target)

    communities = ["public", "private", "community", "monitor"]
    found = []
    if _tool_available("snmpwalk"):
        for comm in communities:
            out, _, rc = _run(["snmpwalk", "-v", "2c", "-c", comm, target, "1.3.6.1.2.1.1.1.0"], timeout=5)
            if rc == 0 and out and "Timeout" not in out:
                found.append({"community": comm, "sysDescr": out.split("=")[-1].strip() if "=" in out else out[:200]})
    return {"target": target, "communities_found": found, "tested": len(communities), "tool": "snmpwalk" if _tool_available("snmpwalk") else "unavailable"}


def _sim_snmp(target):
    rng = _seeded_rng(target)
    if rng.random() < 0.4:
        return {"target": target, "communities_found": [{"community": "public", "sysDescr": "Linux server 5.15.0"}], "tested": 4, "tool": "simulated"}
    return {"target": target, "communities_found": [], "tested": 4, "tool": "simulated"}


# ============================================================
# 3. NFS
# ============================================================

def enumerate_nfs(target, simulate=None):
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_nfs(target)

    if _tool_available("showmount"):
        out, _, rc = _run(["showmount", "-e", target], timeout=10)
        if rc == 0 and out:
            exports = []
            for line in out.splitlines()[1:]:
                parts = line.split()
                if parts:
                    exports.append({"path": parts[0], "access": " ".join(parts[1:])})
            return {"target": target, "exports": exports, "tool": "showmount"}

    return {"target": target, "exports": [], "tool": "unavailable"}


def _sim_nfs(target):
    rng = _seeded_rng(target)
    if rng.random() < 0.3:
        return {"target": target, "exports": [{"path": "/var/shared", "access": "*"}, {"path": "/home", "access": "10.0.0.0/24"}], "tool": "simulated"}
    return {"target": target, "exports": [], "tool": "simulated"}


# ============================================================
# 4. VIRTUAL HOST DISCOVERY
# ============================================================

def discover_vhosts(target, wordlist=None, simulate=None):
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_vhosts(target)

    import ssl
    import urllib.request
    domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    prefixes = wordlist or ["dev", "staging", "test", "api", "admin", "portal", "old", "new", "beta", "internal", "intranet", "vpn"]
    base_url = target if target.startswith("http") else f"http://{target}"

    # Get baseline response
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(base_url, headers={"User-Agent": "PortWatch/1.0", "Host": domain})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            baseline_size = len(resp.read(65536))
    except Exception:
        baseline_size = 0

    found = []
    for prefix in prefixes:
        vhost = f"{prefix}.{domain}"
        try:
            req = urllib.request.Request(base_url, headers={"User-Agent": "PortWatch/1.0", "Host": vhost})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                body = resp.read(65536)
                size = len(body)
                if abs(size - baseline_size) > 100:
                    found.append({"vhost": vhost, "status": resp.getcode(), "size": size})
        except Exception:
            pass

    return {"target": target, "vhosts": found, "checked": len(prefixes), "tool": "host-header"}


def _sim_vhosts(target):
    rng = _seeded_rng(target)
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    if rng.random() < 0.4:
        vhosts = [{"vhost": f"dev.{domain}", "status": 200, "size": rng.randint(2000, 8000)}]
        if rng.random() < 0.3:
            vhosts.append({"vhost": f"staging.{domain}", "status": 200, "size": rng.randint(1000, 5000)})
        return {"target": target, "vhosts": vhosts, "checked": 12, "tool": "simulated"}
    return {"target": target, "vhosts": [], "checked": 12, "tool": "simulated"}


# ============================================================
# 5. OS FINGERPRINTING
# ============================================================

def fingerprint_os(target, simulate=None):
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_os(target)

    if _tool_available("nmap"):
        out, _, rc = _run(["nmap", "-O", "--osscan-guess", target], timeout=60)
        if rc == 0 and out:
            os_matches = re.findall(r'OS details?:\s*(.+)', out)
            aggressive = re.findall(r'Aggressive OS guesses?:\s*(.+)', out)
            return {
                "target": target,
                "os_matches": os_matches,
                "aggressive_guesses": aggressive,
                "raw": out[:2000],
                "tool": "nmap -O",
            }

    return {"target": target, "os_matches": [], "aggressive_guesses": [], "raw": "", "tool": "unavailable (needs root for nmap -O)"}


def _sim_os(target):
    rng = _seeded_rng(target)
    oses = ["Linux 5.15 (Ubuntu 22.04)", "Windows Server 2019", "Linux 4.15 (CentOS 7)", "FreeBSD 13.0"]
    return {"target": target, "os_matches": [rng.choice(oses)], "aggressive_guesses": [], "raw": "(simulated)", "tool": "simulated"}


# ============================================================
# 6. BANNER GRABBING
# ============================================================

def grab_banners(target, ports=None, simulate=None):
    use_sim = simulate if simulate is not None else SIMULATE
    if use_sim:
        return _sim_banners(target, ports)

    check_ports = ports or [21, 22, 25, 80, 110, 143, 443, 3306, 8080]
    results = []
    for port in check_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode("utf-8", "replace").strip()
            sock.close()
            if banner:
                results.append({"port": port, "banner": banner[:500]})
        except Exception:
            pass

    return {"target": target, "banners": results, "tool": "socket"}


def _sim_banners(target, ports):
    rng = _seeded_rng(target)
    banners_db = {
        22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
        21: "220 (vsFTPd 3.0.3)",
        25: "220 mail.example.com ESMTP Postfix",
        80: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
        3306: "5.7.38-log MySQL Community Server",
    }
    check = ports or [21, 22, 25, 80, 3306]
    results = []
    for port in check:
        if port in banners_db and rng.random() < 0.6:
            results.append({"port": port, "banner": banners_db[port]})
    return {"target": target, "banners": results, "tool": "simulated"}


# ============================================================
# COMBINED NETWORK ENUM
# ============================================================

def run_network_enum(target, ports=None, simulate=None):
    return {
        "target": target,
        "smb": enumerate_smb(target, simulate=simulate),
        "snmp": test_snmp(target, simulate=simulate),
        "nfs": enumerate_nfs(target, simulate=simulate),
        "vhosts": discover_vhosts(target, simulate=simulate),
        "os": fingerprint_os(target, simulate=simulate),
        "banners": grab_banners(target, ports=ports, simulate=simulate),
    }
