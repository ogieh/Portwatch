import shutil
import nmap

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


def _check_nmap_available():
    """Raise a clear error early if nmap itself isn't installed/on PATH,
    instead of letting a scan silently fail later."""
    if shutil.which("nmap") is None:
        raise RuntimeError(
            "nmap executable not found on PATH. Install it from nmap.org and "
            "make sure it's added to your system PATH, then restart the terminal."
        )


def run_scan(target):
    """
    Two-phase scan:
      Phase 1 (always runs, fast, reliable): -sV -Pn --top-ports 100
               This alone must correctly find open ports -- matches what a
               plain manual 'nmap -sV --top-ports 100 <target>' would show.
      Phase 2 (best-effort, only on open web ports): runs the NSE script
               bundle scoped to whichever of 80/443/8080/8443 are open.
               If this phase errors or times out, phase 1 results are kept
               and scripts are just left empty -- never silently wiped out.

    Returns a dict shaped exactly as the frontend expects:
    {
      "target": str,
      "ports": [
        {"port": int, "state": str, "service": str, "version": str,
         "risk": "high"|"medium"|"low", "scripts": {...}},
        ...
      ],
      "summary": str
    }
    """
    _check_nmap_available()

    scanner = nmap.PortScanner()

    # ---- Phase 1: reliable port discovery ----
    try:
        scanner.scan(target, arguments="-sV -T4 -Pn --top-ports 100 --host-timeout 60s")
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

    # ---- Phase 2: best-effort NSE scripts on open web ports only ----
    if open_web_ports:
        port_list = ",".join(str(p) for p in open_web_ports)
        try:
            script_scanner = nmap.PortScanner()
            script_scanner.scan(
                target,
                arguments=f"-sV -Pn -p {port_list} --script {NSE_SCRIPTS} --host-timeout 90s",
            )
            if resolved_host in script_scanner.all_hosts():
                script_host_data = script_scanner[resolved_host]
                for proto in script_host_data.all_protocols():
                    for port in script_host_data[proto].keys():
                        info = script_host_data[proto][port]
                        script_output = info.get("script", {})
                        if script_output:
                            for p_entry in ports_out:
                                if p_entry["port"] == port:
                                    p_entry["scripts"] = script_output
        except Exception:
            # Scripts are a bonus, not a requirement -- if this phase fails
            # for any reason, we keep the solid phase 1 port results as-is.
            pass

    summary = generate_summary(target, ports_out)

    return {
        "target": target,
        "resolved_host": resolved_host,
        "ports": ports_out,
        "summary": summary,
    }


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
