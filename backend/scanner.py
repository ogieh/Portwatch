import shutil
import nmap

import authtest

RISK_NOTES = {
    21: "high",
    22: "medium",
    23: "high",
    25: "medium",
    80: "low",
    443: "low",
    3306: "high",
    3389: "high",
    5432: "high",
    6379: "high",
    27017: "high",
}
DEFAULT_RISK = "low"

NSE_SCRIPTS = ",".join([
    "ssl-cert",
    "ssl-enum-ciphers",
    "ssl-dh-params",
    "http-security-headers",
    "http-methods",
    "http-auth-finder",
    "http-vuln-cve2021-41773",
    "http-vuln-cve2017-5638",
])

# Ports worth spending extra time running SSL/HTTP-specific NSE scripts on.
# Extend this if you want scripts to also run against 3300/5510/8443 etc.
WEB_PORTS_FOR_SCRIPTS = {80, 443, 8080, 8443}

# Safe, read-only info scripts for open database/service ports. These run
# automatically (standard/deep profiles) -- they never submit credentials.
DB_SAFE_SCRIPTS = {
    1433: "ms-sql-info",
    3306: "mysql-info",
    5900: "vnc-info",
    6379: "redis-info",
    27017: "mongodb-info",
}

# Credential-checking scripts. These attempt real logins and can lock
# accounts out -- only ever run when the user explicitly opted in.
DB_CRED_SCRIPTS = {
    1433: "ms-sql-brute,ms-sql-empty-password",
    3306: "mysql-brute,mysql-empty-password",
    5432: "pgsql-brute",
    27017: "mongodb-brute",
}
DB_PORTS_FOR_SCRIPTS = set(DB_SAFE_SCRIPTS) | set(DB_CRED_SCRIPTS)

# ---- Scan profiles ----
# "standard" is byte-for-byte the original scan behaviour (the hard-won
# two-phase model): same phase-1 arguments, same script bundle, same
# timeouts. Never change its values when adding new profiles.
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


def _check_nmap_available():
    """Raise a clear error early if nmap itself isn't installed/on PATH,
    instead of letting a scan silently fail later."""
    if shutil.which("nmap") is None:
        raise RuntimeError(
            "nmap executable not found on PATH. Install it from nmap.org and "
            "make sure it's added to your system PATH, then restart the terminal."
        )


def run_scan(target, profile=DEFAULT_PROFILE, credential_checks=False):
    """
    Two-phase scan:
      Phase 1 (always runs, fast, reliable): -sV -Pn --top-ports N
               This alone must correctly find open ports -- matches what a
               plain manual 'nmap -sV --top-ports 100 <target>' would show.
      Phase 2 (best-effort, only on open web ports): runs the NSE script
               bundle scoped to whichever of 80/443/8080/8443 are open.
               If this phase errors or times out, phase 1 results are kept
               and scripts are just left empty -- never silently wiped out.

    profile selects a preset from SCAN_PROFILES ("quick" skips phase 2
    entirely; "standard" is the original behaviour; "deep" widens the port
    range and relaxes timeouts).

    Returns a dict shaped exactly as the frontend expects:
    {
      "target": str,
      "profile": str,
      "credential_checks": {...} | None,
      "ports": [
        {"port": int, "state": str, "service": str, "version": str,
         "risk": "high"|"medium"|"low", "scripts": {...}},
        ...
      ],
      "summary": str
    }
    """
    if profile not in SCAN_PROFILES:
        raise ValueError(
            f"Unknown scan profile '{profile}'. "
            f"Valid profiles: {', '.join(sorted(SCAN_PROFILES))}"
        )
    profile_cfg = SCAN_PROFILES[profile]

    _check_nmap_available()

    scanner = nmap.PortScanner()

    # ---- Phase 1: reliable port discovery ----
    try:
        scanner.scan(target, arguments=profile_cfg["phase1_arguments"])
    except nmap.PortScannerError as e:
        raise RuntimeError(f"Nmap failed to run: {e}")

    scanned_hosts = scanner.all_hosts()
    if not scanned_hosts:
        # Genuinely no response at all -- surface this honestly rather than
        # silently returning an empty port list that looks identical to
        # "scanned fine, nothing open".
        raise RuntimeError(
            f"Nmap could not get any response from '{target}'. The host may be "
            f"unreachable from this network, or blocking all probes."
        )

    resolved_host = scanned_hosts[0]
    host_data = scanner[resolved_host]

    ports_out = []
    open_web_ports = []
    open_db_ports = []

    for proto in host_data.all_protocols():
        for port in sorted(host_data[proto].keys()):
            info = host_data[proto][port]
            product = info.get("product", "")
            version_str = info.get("version", "")
            service_display = (product + " " + version_str).strip() or info.get("name", "unknown")
            state = info.get("state", "unknown")

            ports_out.append({
                "port": port,
                "state": state,
                "service": info.get("name", "unknown"),
                "version": service_display,
                "risk": RISK_NOTES.get(port, DEFAULT_RISK),
                "scripts": {},
            })

            if state == "open" and port in WEB_PORTS_FOR_SCRIPTS:
                open_web_ports.append(port)
            if state == "open" and port in DB_PORTS_FOR_SCRIPTS:
                open_db_ports.append(port)

    # ---- Phase 2: best-effort NSE scripts on open web ports only ----
    if profile_cfg["scripts_enabled"] and open_web_ports:
        port_list = ",".join(str(p) for p in open_web_ports)
        try:
            script_scanner = nmap.PortScanner()
            script_scanner.scan(
                target,
                arguments=(
                    f"-sV -Pn -p {port_list} --script {NSE_SCRIPTS} "
                    f"--host-timeout {profile_cfg['phase2_host_timeout']}"
                ),
            )
            _merge_script_results(script_scanner, resolved_host, ports_out)
        except Exception:
            # Scripts are a bonus, not a requirement -- if this phase fails
            # for any reason, we keep the solid phase 1 port results as-is.
            pass

    # ---- Phase 2b: database/service scripts on open DB ports ----
    # Safe read-only info scripts run automatically with the other scripts;
    # credential-checking scripts only run when explicitly opted in.
    if profile_cfg["scripts_enabled"] and open_db_ports:
        db_script_list = sorted({
            s
            for p in open_db_ports
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
                    f"-sV -Pn -p {','.join(map(str, open_db_ports))} "
                    f"--script {','.join(db_script_list)} "
                    f"--host-timeout {profile_cfg['phase2_host_timeout']}"
                ),
            )
            _merge_script_results(db_scanner, resolved_host, ports_out)
        except Exception:
            pass

    # ---- Phase 3 (opt-in): login rate-limit / lockout probing ----
    credential_result = None
    if credential_checks:
        try:
            credential_result = authtest.run_credential_checks(resolved_host, ports_out)
        except Exception as e:
            credential_result = {
                "enabled": True,
                "http_login_findings": [],
                "db_findings": [],
                "error": f"Credential checks failed: {e}",
            }

    summary = generate_summary(target, ports_out)

    return {
        "target": target,
        "profile": profile,
        "credential_checks": credential_result,
        "resolved_host": resolved_host,
        "ports": ports_out,
        "summary": summary,
    }


def _merge_script_results(nmap_scanner, resolved_host, ports_out):
    """Copy any NSE script output from a best-effort pass into the main
    port list. Never overwrites existing output; never raises upward."""
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
