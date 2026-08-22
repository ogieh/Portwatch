import nmap

# Rules-based risk lookup for common ports. Lowercase risk levels to match
# what the frontend (app.js) expects: 'high', 'medium', 'low'.
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

# NSE scripts run per scan. Kept intentionally small so a scan finishes in a
# reasonable time for a live demo (the frontend hint says 60-300s).
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


def run_scan(target):
    """
    Runs an Nmap scan (with version detection + a curated set of NSE scripts)
    against the target. Returns a dict shaped exactly as the frontend expects:

    {
      "target": str,
      "ports": [
        {
          "port": int,
          "state": "open" | "closed" | "filtered",
          "service": str,
          "version": str,
          "risk": "high" | "medium" | "low",
          "scripts": { "<script-name>": "<raw output>", ... }
        },
        ...
      ]
    }
    """
    scanner = nmap.PortScanner()

    scanner.scan(
        target,
        arguments=f"-sV -T4 --top-ports 100 --script {NSE_SCRIPTS}",
    )

    ports_out = []

    if target in scanner.all_hosts():
        host_data = scanner[target]
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                info = host_data[proto][port]

                product = info.get("product", "")
                version_str = info.get("version", "")
                service_display = (product + " " + version_str).strip() or info.get("name", "unknown")

                scripts = {}
                for script_name, output in info.get("script", {}).items():
                    scripts[script_name] = output

                ports_out.append({
                    "port": port,
                    "state": info.get("state", "unknown"),
                    "service": info.get("name", "unknown"),
                    "version": service_display,
                    "risk": RISK_NOTES.get(port, DEFAULT_RISK),
                    "scripts": scripts,
                })

    summary = generate_summary(target, ports_out)

    return {
        "target": target,
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
