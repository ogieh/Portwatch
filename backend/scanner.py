import re
import shutil
import threading
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
WEB_PORTS_FOR_SCRIPTS = {80, 443, 8080, 8443}

# --------------------------------------------------------------------------
# Curated software/version knowledge base.
# This is NOT a live CVE feed -- it's a hand-maintained table of well-known,
# high-confidence facts about specific product/version combinations. If a
# detected service+version isn't in here, the tool says so plainly instead
# of guessing. Extend this list over time as you research more services.
#
# Matching: "product" is matched case-insensitively as a substring of the
# nmap-reported product name. "max_version" uses simple dotted-version
# comparison -- any detected version <= max_version is flagged.
# --------------------------------------------------------------------------
KNOWN_OUTDATED_SOFTWARE = [
    {
        "product": "nginx",
        "max_version": "1.24.0",
        "note": (
            "This version of nginx is past its supported lifecycle and is missing "
            "security patches issued in later releases. Known issues affecting "
            "older 1.20.x-1.22.x branches include heap memory corruption bugs and "
            "HTTP/2 request-handling vulnerabilities that can be used for denial "
            "of service or, in some configurations, remote code execution."
        ),
    },
    {
        "product": "apache",
        "max_version": "2.4.58",
        "note": (
            "This Apache HTTP Server version predates several published security "
            "fixes. Depending on exact build and modules enabled, this can include "
            "request-smuggling and memory-disclosure issues. Upgrading to the "
            "latest 2.4.x release is recommended."
        ),
    },
    {
        "product": "openssh",
        "max_version": "9.3",
        "note": (
            "Older OpenSSH releases are affected by the widely reported "
            "'regreSSHion' remote code execution vulnerability (CVE-2024-6387) in "
            "some builds, and generally lack hardening improvements from newer "
            "releases. SSH exposure should also be reviewed for whether it needs "
            "to be internet-facing at all."
        ),
    },
    {
        "product": "mysql",
        "max_version": "8.0.34",
        "note": (
            "Older MySQL versions may be missing patches for known privilege "
            "escalation and authentication bypass issues. Database engines should "
            "generally not be directly reachable from the public internet."
        ),
    },
    {
        "product": "php",
        "max_version": "8.1.0",
        "note": (
            "PHP versions before 8.1 have reached or are approaching end-of-life "
            "and no longer receive security updates from the PHP project, leaving "
            "any vulnerabilities discovered after end-of-life permanently unpatched."
        ),
    },
    {
        "product": "vsftpd",
        "max_version": "3.0.3",
        "note": (
            "Older vsftpd builds have had backdoor and denial-of-service issues "
            "historically. FTP itself also transmits credentials in plaintext and "
            "should generally be replaced with SFTP where possible."
        ),
    },
    {
        "product": "postgresql",
        "max_version": "14.10",
        "note": (
            "Older PostgreSQL point releases are missing fixes for privilege "
            "escalation and memory-safety issues published in later minor "
            "releases. As with other database engines, direct public exposure "
            "is a significant risk on its own regardless of patch level."
        ),
    },
]

# Plain-English, non-technical explanation of what a port/service generally is,
# used to build the narrative report for non-technical readers.
SERVICE_EXPLANATIONS = {
    21: "File Transfer Protocol (FTP), an old method for uploading and downloading files. It typically sends credentials without encryption.",
    22: "Secure Shell (SSH), used by administrators to remotely log into and control a server.",
    23: "Telnet, a very old remote-access protocol that sends everything, including passwords, with no encryption at all.",
    25: "Simple Mail Transfer Protocol (SMTP), used for sending email.",
    80: "a standard, unencrypted web server (HTTP).",
    443: "a standard, encrypted web server (HTTPS).",
    3306: "a MySQL database, which stores application data.",
    3389: "Remote Desktop Protocol (RDP), used to remotely control a Windows machine's desktop.",
    5432: "a PostgreSQL database, which stores application data.",
    6379: "a Redis database, often used for caching, which by default has no authentication.",
    27017: "a MongoDB database, which stores application data.",
}


def _check_nmap_available():
    if shutil.which("nmap") is None:
        raise RuntimeError(
            "nmap executable not found on PATH. Install it from nmap.org and "
            "make sure it's added to your system PATH, then restart the terminal."
        )


def _version_tuple(v):
    """Turn '1.20.1' into (1, 20, 1) for comparison. Non-numeric parts are
    treated as 0 so odd version strings don't crash the comparison."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _check_known_vulnerabilities(product, version):
    """Look up product/version against the curated knowledge base.
    Returns a note string if a match is found and the version looks
    outdated, otherwise None. Never invents information for products
    it doesn't recognise."""
    if not product or not version:
        return None

    product_lower = product.lower()
    for entry in KNOWN_OUTDATED_SOFTWARE:
        if entry["product"] in product_lower:
            try:
                if _version_tuple(version) <= _version_tuple(entry["max_version"]):
                    return entry["note"]
            except Exception:
                return None
    return None


def run_scan(target, on_progress=None):
    """
    Two-phase scan:
      Phase 1 (always runs, fast, reliable): -sV -Pn --top-ports 100
      Phase 2 (best-effort, only on open web ports): NSE script bundle.
    Returns dict shaped for the frontend, now including a richer
    'narrative_summary' field alongside the existing 'summary'.

    on_progress(stage: str) is called at each stage transition, if provided,
    so a caller (e.g. a background job runner) can report real progress
    instead of a fake/simulated bar.
    """
    def report(stage):
        if on_progress:
            try:
                on_progress(stage)
            except Exception:
                pass

    _check_nmap_available()

    scanner = nmap.PortScanner()

    report("resolving")

    # Watchdog: nmap's own --host-timeout only starts once nmap begins
    # probing. DNS resolution or an unresponsive network can hang *before*
    # that, with no timeout at all. Run phase 1 in a background thread with
    # a hard wall-clock cap so a broken target can never hang forever.
    result_holder = {}
    error_holder = {}

    def _do_phase1():
        try:
            scanner.scan(target, arguments="-sV -T4 -Pn --top-ports 100 --host-timeout 60s")
            result_holder["done"] = True
        except Exception as e:
            error_holder["error"] = e

    report("port_scan")
    t = threading.Thread(target=_do_phase1, daemon=True)
    t.start()
    t.join(timeout=90)  # hard cap: DNS/network hang can't exceed this

    if t.is_alive():
        raise RuntimeError(
            f"Scan of '{target}' timed out after 90 seconds with no response "
            f"(this usually means DNS resolution or the network connection "
            f"itself is hanging, not just a slow host). Double-check the "
            f"target is reachable and try again."
        )

    if "error" in error_holder:
        raise RuntimeError(f"Nmap failed to run: {error_holder['error']}")

    scanned_hosts = scanner.all_hosts()
    if not scanned_hosts:
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

            vuln_note = _check_known_vulnerabilities(product, version_str)

            ports_out.append({
                "port": port,
                "state": state,
                "service": info.get("name", "unknown"),
                "version": service_display,
                "risk": RISK_NOTES.get(port, DEFAULT_RISK),
                "scripts": {},
                "known_issue": vuln_note,  # None if nothing matched -- never fabricated
            })

            if state == "open" and port in WEB_PORTS_FOR_SCRIPTS:
                open_web_ports.append(port)

    if open_web_ports:
        report("service_scripts")
        port_list = ",".join(str(p) for p in open_web_ports)
        script_scanner = nmap.PortScanner()
        script_result = {}
        script_error = {}

        def _do_phase2():
            try:
                script_scanner.scan(
                    target,
                    arguments=f"-sV -Pn -p {port_list} --script {NSE_SCRIPTS} --host-timeout 90s",
                )
                script_result["done"] = True
            except Exception as e:
                script_error["error"] = e

        t2 = threading.Thread(target=_do_phase2, daemon=True)
        t2.start()
        t2.join(timeout=120)  # scripts are best-effort; never let them hang forever

        # Whether it timed out, errored, or succeeded, phase 1 results are
        # never touched -- scripts only ever *add* data on top of them.
        if t2.is_alive() or "error" in script_error:
            pass
        elif resolved_host in script_scanner.all_hosts():
            script_host_data = script_scanner[resolved_host]
            for proto in script_host_data.all_protocols():
                for port in script_host_data[proto].keys():
                    info = script_host_data[proto][port]
                    script_output = info.get("script", {})
                    if script_output:
                        for p_entry in ports_out:
                            if p_entry["port"] == port:
                                p_entry["scripts"] = script_output

    report("finalizing")
    summary = generate_summary(target, ports_out)
    narrative = generate_narrative_report(target, ports_out)
    report("done")

    return {
        "target": target,
        "resolved_host": resolved_host,
        "ports": ports_out,
        "summary": summary,
        "narrative_summary": narrative,
    }


def generate_summary(target, ports):
    """Short one-line summary, unchanged -- used for history table rows."""
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


def generate_narrative_report(target, ports):
    """
    Multi-paragraph, plain-English report intended for a non-technical
    reader (manager/client), sitting alongside -- not replacing -- the raw
    technical port table. Every claim here is derived directly from actual
    scan data or the curated knowledge base; nothing is invented.
    """
    open_ports = [p for p in ports if p["state"] == "open"]

    paragraphs = []

    # --- Opening paragraph ---
    if not open_ports:
        paragraphs.append(
            f"A security scan of {target} was performed and did not find any open, "
            f"internet-reachable services within the ports checked. This is a "
            f"positive result: it means there is currently nothing obvious for an "
            f"attacker to connect to on this host, at least within the range tested."
        )
        return "\n\n".join(paragraphs)

    paragraphs.append(
        f"A security scan of {target} identified {len(open_ports)} open network "
        f"port(s). Each open port represents a service that is reachable from "
        f"outside the organisation, and each one is a potential entry point that "
        f"should be reviewed to confirm it is intentional and properly secured."
    )

    # --- Per-finding explanation, in plain English ---
    for p in open_ports:
        plain_desc = SERVICE_EXPLANATIONS.get(
            p["port"],
            f"a service identified as '{p['service']}', which does not have a "
            f"plain-language description on file and should be reviewed manually."
        )
        para = (
            f"Port {p['port']} is running {plain_desc} "
            f"The detected software is reported as \"{p['version']}\"."
        )

        if p.get("known_issue"):
            para += (
                f" This specific version is known to be outdated. {p['known_issue']}"
            )
        else:
            para += (
                " No specific outdated-version issue was matched against this tool's "
                "curated reference list for this software; that does not guarantee it "
                "is fully up to date, only that it isn't one of the specific cases this "
                "tool currently recognises. A manual check of the vendor's latest "
                "release notes is recommended."
            )

        if p["risk"] == "high":
            para += (
                " Overall, this is considered a high-risk finding and should be "
                "prioritised for remediation or access restriction."
            )
        elif p["risk"] == "medium":
            para += " Overall, this is considered a moderate-risk finding worth reviewing."

        paragraphs.append(para)

    # --- Closing paragraph ---
    high_count = len([p for p in open_ports if p["risk"] == "high"])
    if high_count:
        paragraphs.append(
            f"In summary, {high_count} of the findings above are considered "
            f"high risk and warrant prompt attention. Addressing exposed "
            f"administrative or database services first, followed by outdated "
            f"software, is generally the most effective way to reduce risk quickly."
        )
    else:
        paragraphs.append(
            "In summary, no high-risk findings were identified in this scan, though "
            "the items above are still worth reviewing to confirm each exposed "
            "service is intentional and necessary."
        )

    return "\n\n".join(paragraphs)
