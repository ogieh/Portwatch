"""
Vulnerability intelligence for PortWatch Pro.

Enriches raw scan findings with a curated knowledge base:
  - Known-bad service versions mapped to real CVE identifiers + CVSS + fix.
  - Exposure guidance for risky services (Telnet, Redis, RDP, DB ports...).
  - NSE http-vuln-* hits mapped to their canonical CVE record.

This is an offline, deterministic knowledge layer (no external API calls, so it
works air-gapped and in a demo). It is intentionally conservative: it only
asserts a CVE when the detected version string clearly matches a vulnerable
range. Everything it returns carries a `confidence` field so a report can be
honest about version-string matching vs confirmed script output.

Each finding:
{
  "port": int, "service": str, "title": str, "severity": "critical|high|medium|low",
  "cvss": float|None, "cve": [str,...], "confidence": "confirmed|likely|informational",
  "evidence": str, "remediation": str
}
"""

import re

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---- 1. NSE script-confirmed CVEs (highest confidence: nmap proved it) ----
NSE_CVE_MAP = {
    "http-vuln-cve2021-41773": {
        "cve": ["CVE-2021-41773"],
        "title": "Apache HTTP Server path traversal / RCE",
        "severity": "critical",
        "cvss": 9.8,
        "remediation": "Upgrade Apache httpd to 2.4.51 or later. Ensure "
                       "'Require all denied' is set for filesystem roots outside the docroot.",
    },
    "http-vuln-cve2017-5638": {
        "cve": ["CVE-2017-5638"],
        "title": "Apache Struts 2 Jakarta Multipart RCE",
        "severity": "critical",
        "cvss": 10.0,
        "remediation": "Upgrade Apache Struts to 2.3.32 / 2.5.10.1 or later, or remove the "
                       "Jakarta Multipart parser if unused.",
    },
}


# ---- 2. Version-string → CVE knowledge base (likely: matched on banner) ----
# (regex on the version string, human title, cve list, severity, cvss, fix)
VERSION_CVES = [
    {
        "match": re.compile(r"vsftpd\s*2\.3\.4", re.I),
        "cve": ["CVE-2011-2523"],
        "title": "vsftpd 2.3.4 backdoor command execution",
        "severity": "critical", "cvss": 10.0,
        "remediation": "Remove the trojaned build immediately and reinstall vsftpd from a trusted "
                       "package source (>= 3.0). Audit the host for compromise.",
    },
    {
        "match": re.compile(r"OpenSSH\s*7\.[0-4]", re.I),
        "cve": ["CVE-2016-10009", "CVE-2016-10012"],
        "title": "OpenSSH < 7.4 agent / privilege-separation flaws",
        "severity": "medium", "cvss": 7.5,
        "remediation": "Upgrade OpenSSH to 8.x or later. Disable agent forwarding where not required.",
    },
    {
        "match": re.compile(r"(Apache httpd|Apache)\s*2\.4\.(2\d|3\d|4[0-9])\b", re.I),
        "cve": ["CVE-2021-40438"],
        "title": "Apache httpd < 2.4.49 mod_proxy SSRF",
        "severity": "high", "cvss": 9.0,
        "remediation": "Upgrade Apache httpd to 2.4.49+ (ideally the latest 2.4.x). Review mod_proxy config.",
    },
    {
        "match": re.compile(r"nginx\s*1\.(1[0-9]|20)\.", re.I),
        "cve": ["CVE-2021-23017"],
        "title": "nginx resolver off-by-one heap write",
        "severity": "high", "cvss": 8.1,
        "remediation": "Upgrade nginx to 1.21.0 or later.",
    },
    {
        "match": re.compile(r"(MySQL|MariaDB)\s*5\.", re.I),
        "cve": ["CVE-2016-6662"],
        "title": "MySQL/MariaDB 5.x privilege escalation class",
        "severity": "high", "cvss": 8.8,
        "remediation": "Upgrade to a supported 8.x release; restrict FILE privilege and secure my.cnf ownership.",
    },
    {
        "match": re.compile(r"Redis\s*(4\.|5\.0)", re.I),
        "cve": ["CVE-2022-0543"],
        "title": "Redis Lua sandbox escape (Debian/Ubuntu builds)",
        "severity": "critical", "cvss": 10.0,
        "remediation": "Upgrade Redis to a patched release and never expose Redis to untrusted networks. "
                       "Require authentication and bind to localhost / private interfaces.",
    },
    {
        "match": re.compile(r"Exim\s*4\.(8[7-9]|9[01])\b", re.I),
        "cve": ["CVE-2019-10149"],
        "title": "Exim 4.87 to 4.91 remote command execution",
        "severity": "critical", "cvss": 9.8,
        "remediation": "Upgrade Exim to 4.92 or later.",
    },
    {
        "match": re.compile(r"ProFTPD\s*1\.3\.5", re.I),
        "cve": ["CVE-2015-3306"],
        "title": "ProFTPD 1.3.5 mod_copy arbitrary file read/write",
        "severity": "critical", "cvss": 10.0,
        "remediation": "Upgrade ProFTPD to 1.3.5a+ and disable mod_copy if unused.",
    },
]


# ---- 3. Exposure guidance for inherently risky open services ----
EXPOSURE_GUIDANCE = {
    23:   ("Telnet exposed", "high", "Telnet transmits credentials in cleartext. "
           "Disable it and use SSH."),
    21:   ("FTP exposed", "medium", "Plain FTP is unencrypted. Prefer SFTP/FTPS and "
           "restrict access to trusted networks."),
    3389: ("RDP exposed to network", "high", "Expose RDP only via VPN or a bastion. "
           "Enforce Network Level Authentication and account lockout."),
    3306: ("MySQL exposed to network", "high", "Databases should never be internet-facing. "
           "Bind to localhost / private subnet and firewall the port."),
    5432: ("PostgreSQL exposed to network", "high", "Restrict to private networks; enforce "
           "TLS and strong authentication in pg_hba.conf."),
    6379: ("Redis exposed to network", "critical", "Unauthenticated Redis is trivially abused. "
           "Require a password, enable protected-mode, bind to localhost."),
    27017:("MongoDB exposed to network", "high", "Enable authentication and bind to private "
           "interfaces; unauthenticated MongoDB leaks entire databases."),
    5900: ("VNC exposed to network", "high", "Tunnel VNC over SSH/VPN and require strong "
           "authentication; raw VNC auth is weak."),
    25:   ("SMTP exposed", "low", "Ensure the server is not an open relay and enforces TLS."),
}


def _service_label(port_entry):
    return port_entry.get("version") or port_entry.get("service") or "unknown"


def enrich(ports, credential_checks=None):
    """
    Build the vulnerability-intelligence list for a scan.
    Deduplicated by (port, cve-tuple/title), sorted worst-first.
    """
    findings = []
    seen = set()

    def push(f):
        key = (f["port"], tuple(f.get("cve") or ()), f["title"])
        if key in seen:
            return
        seen.add(key)
        findings.append(f)

    for p in ports:
        if p.get("state") != "open":
            continue
        port = p.get("port")
        label = _service_label(p)
        scripts = p.get("scripts") or {}

        # 1. Script-confirmed CVEs
        for name, out in scripts.items():
            if not isinstance(out, str) or not out:
                continue
            if name in NSE_CVE_MAP and "VULNERABLE" in out.upper():
                rec = NSE_CVE_MAP[name]
                push({
                    "port": port, "service": label, "title": rec["title"],
                    "severity": rec["severity"], "cvss": rec["cvss"],
                    "cve": rec["cve"], "confidence": "confirmed",
                    "evidence": f"NSE script {name} reported VULNERABLE.",
                    "remediation": rec["remediation"],
                })

        # 2. Version-string CVE matches
        for rec in VERSION_CVES:
            if rec["match"].search(label):
                push({
                    "port": port, "service": label, "title": rec["title"],
                    "severity": rec["severity"], "cvss": rec["cvss"],
                    "cve": rec["cve"], "confidence": "likely",
                    "evidence": f"Detected version banner '{label}' falls in a known-vulnerable range.",
                    "remediation": rec["remediation"],
                })

        # 3. Exposure guidance
        if port in EXPOSURE_GUIDANCE:
            title, sev, fix = EXPOSURE_GUIDANCE[port]
            push({
                "port": port, "service": label, "title": title,
                "severity": sev, "cvss": None, "cve": [],
                "confidence": "informational",
                "evidence": f"Port {port} ({p.get('service')}) is open to the scanned network.",
                "remediation": fix,
            })

    findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), -(f.get("cvss") or 0)))
    return findings


def summarize(findings):
    """Small rollup used by the dashboard and report headers."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cve_set = set()
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        for c in f.get("cve") or []:
            cve_set.add(c)
    return {
        "total": len(findings),
        "counts": counts,
        "unique_cves": sorted(cve_set),
        "confirmed": sum(1 for f in findings if f.get("confidence") == "confirmed"),
    }
