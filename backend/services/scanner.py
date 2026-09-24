"""
Scan engine for PortWatch Pro.

This is the original PortWatch two-phase nmap engine, preserved intact, with one
addition: a simulation mode. When nmap is unavailable (no install / no root) or
PORTWATCH_SIMULATE is set, run_scan() produces realistic synthetic scan results
in the exact same shape, so every feature above it (scoring, compliance,
diffing, reports, dashboards, schedules) is fully demonstrable anywhere.

The real engine is byte-for-byte the proven original where it matters:
same phase-1 arguments, same NSE bundle, same timeouts, same output dict.
"""

import shutil
import random
import hashlib

try:
    import nmap
except Exception:  # python-nmap not installed at all
    nmap = None

RISK_NOTES = {
    21: "high", 22: "medium", 23: "high", 25: "medium",
    80: "low", 443: "low",
    3306: "high", 3389: "high", 5432: "high", 6379: "high", 27017: "high",
}
DEFAULT_RISK = "low"

NSE_SCRIPTS = ",".join([
    "ssl-cert", "ssl-enum-ciphers", "ssl-dh-params",
    "http-security-headers", "http-methods", "http-auth-finder",
    "http-vuln-cve2021-41773", "http-vuln-cve2017-5638",
])

WEB_PORTS_FOR_SCRIPTS = {80, 443, 8080, 8443}

DB_SAFE_SCRIPTS = {
    1433: "ms-sql-info", 3306: "mysql-info", 5900: "vnc-info",
    6379: "redis-info", 27017: "mongodb-info",
}
DB_CRED_SCRIPTS = {
    1433: "ms-sql-brute,ms-sql-empty-password",
    3306: "mysql-brute,mysql-empty-password",
    5432: "pgsql-brute", 27017: "mongodb-brute",
}
DB_PORTS_FOR_SCRIPTS = set(DB_SAFE_SCRIPTS) | set(DB_CRED_SCRIPTS)

SCAN_PROFILES = {
    "quick": {
        "label": "Quick",
        "description": "Top 20 ports, no scripts",
        "phase1_arguments": "-sV -T4 -Pn --top-ports 20 --host-timeout 60s",
        "scripts_enabled": False,
        "phase2_host_timeout": "90s",
    },
    "standard": {
        "label": "Standard",
        "description": "Top 100 ports + web scripts",
        "phase1_arguments": "-sV -T4 -Pn --top-ports 100 --host-timeout 60s",
        "scripts_enabled": True,
        "phase2_host_timeout": "90s",
    },
    "deep": {
        "label": "Deep",
        "description": "Top 1000 ports + web scripts, longer timeouts",
        "phase1_arguments": "-sV -T4 -Pn --top-ports 1000 --host-timeout 240s",
        "scripts_enabled": True,
        "phase2_host_timeout": "180s",
    },
}
DEFAULT_PROFILE = "standard"


def nmap_available():
    return nmap is not None and shutil.which("nmap") is not None


def _check_nmap_available():
    if not nmap_available():
        raise RuntimeError(
            "nmap executable not found on PATH. Install it from nmap.org and "
            "make sure it's added to your system PATH, then restart the terminal."
        )


import authtest  # preserved original credential/lockout module


class ScanCancelled(Exception):
    """Raised between phases when the caller asked for the scan to stop."""


def _noop_cancel_check():
    return False


def run_scan(target, profile=DEFAULT_PROFILE, credential_checks=False, simulate=None,
             scan_type="connect", cancel_check=None):
    """
    Returns the canonical scan dict:
    {
      "target", "profile", "credential_checks", "resolved_host",
      "ports": [{"port","state","service","version","risk","scripts"}...],
      "summary", "engine": "nmap"|"simulated"
    }

    scan_type: "connect" adds -sT (works without root); "syn" adds -sS
    (needs root or CAP_NET_RAW). cancel_check: zero-arg callable polled
    between phases; when it returns True the scan raises ScanCancelled.
    """
    if profile not in SCAN_PROFILES:
        raise ValueError(
            f"Unknown scan profile '{profile}'. "
            f"Valid profiles: {', '.join(sorted(SCAN_PROFILES))}"
        )
    if scan_type not in ("connect", "syn"):
        raise ValueError("scan_type must be 'connect' or 'syn'")

    use_sim = simulate if simulate is not None else (not nmap_available())
    if use_sim:
        # Simulation never touches the network, so the guard is not required
        # for safety; we still normalize obvious garbage.
        return _simulate_scan(target, profile, credential_checks)

    # Real scans must pass the target guard: no loopback, link-local, or
    # cloud-metadata endpoints, and no private ranges unless explicitly
    # enabled for an internal engagement. Raises TargetRejected on refusal.
    from core.target_guard import validate_target
    validate_target(target, resolve=True)

    return _real_scan(target, profile, credential_checks, scan_type,
                      cancel_check or _noop_cancel_check)


def scan_type_flag(scan_type):
    return "-sT" if scan_type == "connect" else "-sS"


# ───────────────────────── REAL ENGINE (preserved) ─────────────────────────

def _real_scan(target, profile, credential_checks, scan_type="connect",
               cancel_check=_noop_cancel_check):
    profile_cfg = SCAN_PROFILES[profile]
    _check_nmap_available()
    stype = scan_type_flag(scan_type)

    scanner = nmap.PortScanner()
    try:
        scanner.scan(target, arguments=f"{stype} {profile_cfg['phase1_arguments']}")
    except nmap.PortScannerError as e:
        raise RuntimeError(f"Nmap failed to run: {e}")

    scanned_hosts = scanner.all_hosts()
    if not scanned_hosts:
        raise RuntimeError(
            f"Nmap could not get any response from '{target}'. The host may be "
            f"unreachable from this network, or blocking all probes."
        )

    resolved_host = scanned_hosts[0]
    host_data = scanner[resolved_host]

    ports_out, open_web_ports, open_db_ports = [], [], []
    for proto in host_data.all_protocols():
        for port in sorted(host_data[proto].keys()):
            info = host_data[proto][port]
            product = info.get("product", "")
            version_str = info.get("version", "")
            service_display = (product + " " + version_str).strip() or info.get("name", "unknown")
            state = info.get("state", "unknown")
            ports_out.append({
                "port": port, "state": state,
                "service": info.get("name", "unknown"),
                "version": service_display,
                "risk": RISK_NOTES.get(port, DEFAULT_RISK),
                "scripts": {},
            })
            if state == "open" and port in WEB_PORTS_FOR_SCRIPTS:
                open_web_ports.append(port)
            if state == "open" and port in DB_PORTS_FOR_SCRIPTS:
                open_db_ports.append(port)

    if cancel_check():
        raise ScanCancelled("Scan cancelled after port discovery")

    if profile_cfg["scripts_enabled"] and open_web_ports:
        port_list = ",".join(str(p) for p in open_web_ports)
        try:
            script_scanner = nmap.PortScanner()
            script_scanner.scan(
                target,
                arguments=(
                    f"{stype} -sV -Pn -p {port_list} --script {NSE_SCRIPTS} "
                    f"--host-timeout {profile_cfg['phase2_host_timeout']}"
                ),
            )
            _merge_script_results(script_scanner, resolved_host, ports_out)
        except Exception:
            pass

    if cancel_check():
        raise ScanCancelled("Scan cancelled after web script phase")

    if profile_cfg["scripts_enabled"] and open_db_ports:
        db_script_list = sorted({
            s for p in open_db_ports
            for s in (
                ([DB_SAFE_SCRIPTS[p]] if p in DB_SAFE_SCRIPTS else []) +
                ([DB_CRED_SCRIPTS[p]] if credential_checks and p in DB_CRED_SCRIPTS else [])
            )
        })
        try:
            db_scanner = nmap.PortScanner()
            db_scanner.scan(
                target,
                arguments=(
                    f"{stype} -sV -Pn -p {','.join(map(str, open_db_ports))} "
                    f"--script {','.join(db_script_list)} "
                    f"--host-timeout {profile_cfg['phase2_host_timeout']}"
                ),
            )
            _merge_script_results(db_scanner, resolved_host, ports_out)
        except Exception:
            pass

    if cancel_check():
        raise ScanCancelled("Scan cancelled before credential checks")

    credential_result = None
    if credential_checks:
        try:
            credential_result = authtest.run_credential_checks(resolved_host, ports_out)
        except Exception as e:
            credential_result = {
                "enabled": True, "http_login_findings": [], "db_findings": [],
                "error": f"Credential checks failed: {e}",
            }

    return {
        "target": target,
        "profile": profile,
        "credential_checks": credential_result,
        "resolved_host": resolved_host,
        "ports": ports_out,
        "summary": generate_summary(target, ports_out),
        "engine": "nmap",
    }


def _merge_script_results(nmap_scanner, resolved_host, ports_out):
    try:
        if resolved_host not in nmap_scanner.all_hosts():
            return
        host_data = nmap_scanner[resolved_host]
        for proto in host_data.all_protocols():
            for port in host_data[proto].keys():
                info = host_data[proto][port]
                script_output = info.get("script", {})
                if not script_output:
                    continue
                for p_entry in ports_out:
                    if p_entry["port"] == port and not p_entry["scripts"]:
                        p_entry["scripts"] = script_output
    except Exception:
        pass


# ───────────────────────── SIMULATION FALLBACK ─────────────────────────
# Deterministic per-target (a target always looks the same across scans unless
# a deep profile reveals more), but varied across different targets. This makes
# demos, screenshots, diffs and the dashboard all behave realistically.

_SERVICE_CATALOG = {
    21:   ("ftp", ["vsftpd 2.3.4", "ProFTPD 1.3.5", "Pure-FTPd"]),
    22:   ("ssh", ["OpenSSH 7.4", "OpenSSH 8.9p1", "OpenSSH 9.6p1"]),
    23:   ("telnet", ["Linux telnetd"]),
    25:   ("smtp", ["Postfix smtpd", "Exim 4.94"]),
    53:   ("domain", ["ISC BIND 9.11", "dnsmasq 2.80"]),
    80:   ("http", ["Apache httpd 2.4.29", "nginx 1.18.0", "nginx 1.25.3"]),
    110:  ("pop3", ["Dovecot pop3d"]),
    143:  ("imap", ["Dovecot imapd"]),
    443:  ("https", ["nginx 1.18.0", "Apache httpd 2.4.52", "nginx 1.25.3"]),
    3306: ("mysql", ["MySQL 5.7.38", "MariaDB 10.5.18"]),
    3389: ("ms-wbt-server", ["Microsoft Terminal Services"]),
    5432: ("postgresql", ["PostgreSQL 12.9", "PostgreSQL 15.2"]),
    6379: ("redis", ["Redis 5.0.7", "Redis 7.0.11"]),
    8080: ("http-proxy", ["Apache Tomcat 9.0.54", "Jetty 9.4"]),
    8443: ("https-alt", ["nginx 1.20.1"]),
    27017:("mongodb", ["MongoDB 4.4.6", "MongoDB 6.0.4"]),
}

_PROFILE_PORT_POOL = {
    "quick":    [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389],
    "standard": [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443, 27017],
    "deep":     list(_SERVICE_CATALOG.keys()),
}


def _seeded_rng(target, profile):
    seed = int(hashlib.sha256(f"{target}|{profile}".encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)


def _simulate_scan(target, profile, credential_checks):
    rng = _seeded_rng(target, profile)
    pool = _PROFILE_PORT_POOL[profile]

    # Decide how many ports look open, deterministic per target.
    open_count = rng.randint(2, min(7, len(pool)))
    open_ports = sorted(rng.sample(pool, open_count))

    ports_out = []
    open_web_ports, open_db_ports = [], []
    for port in sorted(pool):
        name, versions = _SERVICE_CATALOG[port]
        is_open = port in open_ports
        state = "open" if is_open else rng.choice(["closed", "filtered"])
        ports_out.append({
            "port": port,
            "state": state,
            "service": name,
            "version": rng.choice(versions) if is_open else name,
            "risk": RISK_NOTES.get(port, DEFAULT_RISK),
            "scripts": {},
        })
        if is_open and port in WEB_PORTS_FOR_SCRIPTS:
            open_web_ports.append(port)
        if is_open and port in DB_PORTS_FOR_SCRIPTS:
            open_db_ports.append(port)

    if SCAN_PROFILES[profile]["scripts_enabled"]:
        _simulate_scripts(rng, ports_out, open_web_ports, open_db_ports, credential_checks)

    credential_result = None
    if credential_checks:
        credential_result = _simulate_credentials(rng, ports_out, target, open_web_ports)

    return {
        "target": target,
        "profile": profile,
        "credential_checks": credential_result,
        "resolved_host": target,
        "ports": ports_out,
        "summary": generate_summary(target, ports_out),
        "engine": "simulated",
    }


def _simulate_scripts(rng, ports_out, open_web_ports, open_db_ports, credential_checks):
    by_port = {p["port"]: p for p in ports_out}

    for port in open_web_ports:
        entry = by_port[port]
        scripts = {}
        # SSL findings on TLS ports
        if port in (443, 8443):
            scripts["ssl-cert"] = "Subject: commonName=" + rng.choice(
                ["example.com", "*.internal.local", "vpn.corp.net"]
            ) + "\nNot valid after: 2026-12-01"
            if rng.random() < 0.4:
                scripts["ssl-enum-ciphers"] = (
                    "TLSv1.0:\n  ciphers:\n    TLS_RSA_WITH_RC4_128_SHA - weak\n"
                    "  least strength: weak"
                )
            if rng.random() < 0.25:
                scripts["ssl-dh-params"] = "VULNERABLE: Diffie-Hellman Key Exchange (Logjam) - weak"
        # HTTP header hygiene
        if rng.random() < 0.7:
            missing = rng.sample(
                ["Content-Security-Policy", "Strict-Transport-Security",
                 "X-Frame-Options", "X-Content-Type-Options",
                 "Referrer-Policy", "Permissions-Policy"],
                rng.randint(1, 4),
            )
            scripts["http-security-headers"] = "Missing headers: " + ", ".join(missing)
        if rng.random() < 0.3:
            scripts["http-methods"] = "Supported Methods: GET HEAD POST OPTIONS " + rng.choice(
                ["PUT", "DELETE", "TRACE"]
            )
        # Occasional real-CVE style hit
        if rng.random() < 0.18:
            cve = rng.choice(["http-vuln-cve2021-41773", "http-vuln-cve2017-5638"])
            scripts[cve] = f"VULNERABLE:\n  {cve} path traversal / RCE confirmed"
        entry["scripts"] = scripts

    for port in open_db_ports:
        entry = by_port[port]
        safe = DB_SAFE_SCRIPTS.get(port)
        scripts = {}
        if safe:
            scripts[safe] = f"{entry['service']} info: version {entry['version']}"
        if credential_checks and port in DB_CRED_SCRIPTS:
            if rng.random() < 0.35:
                empty_script = f"{entry['service']}-empty-password"
                scripts[empty_script] = "Accounts with empty password: root"
        entry["scripts"] = {**entry.get("scripts", {}), **scripts}


def _simulate_credentials(rng, ports_out, target, open_web_ports):
    http_findings = []
    if open_web_ports:
        verdicts = [
            ("none_observed", f"No throttling, lockout or CAPTCHA observed within 5 failed attempts."),
            ("throttled", "Server returned 429 during repeated failures."),
            ("lockout", "Lockout-style response after repeated failures."),
            ("captcha", "CAPTCHA challenge appeared after repeated failures."),
        ]
        verdict, detail = rng.choice(verdicts)
        http_findings.append({
            "url": f"http://{target}/login",
            "attempts": 5,
            "status_codes": [200, 200, 200, 200, 200],
            "verdict": verdict,
            "detail": detail,
        })

    db_findings = []
    for p in ports_out:
        for name in (p.get("scripts") or {}):
            if name.endswith("-empty-password"):
                db_findings.append({
                    "port": p["port"], "check": name, "vulnerable": True,
                    "detail": "Account accepts an empty password.",
                })
    return {"enabled": True, "http_login_findings": http_findings, "db_findings": db_findings}


# ───────────────────────── SHARED SUMMARY ─────────────────────────

def generate_summary(target, ports):
    open_ports = [p for p in ports if p["state"] == "open"]
    if not open_ports:
        return f"No open ports were detected on {target} in the scanned range."

    high = [p for p in open_ports if p["risk"] == "high"]
    lines = [f"Scan of {target} found {len(open_ports)} open port(s)."]
    if high:
        port_list = ", ".join(str(p["port"]) for p in high)
        lines.append(f"High risk: port(s) {port_list} are exposed and should be reviewed as a priority.")
    else:
        lines.append("No high-risk services were detected among the open ports.")

    vuln_hits = [
        (p["port"], name)
        for p in open_ports
        for name, out in p["scripts"].items()
        if name.startswith("http-vuln-") and out and "VULNERABLE" in out.upper()
    ]
    if vuln_hits:
        details = ", ".join(f"{name} on port {port}" for port, name in vuln_hits)
        lines.append(f"Vulnerability scripts flagged: {details}.")
    return " ".join(lines)
