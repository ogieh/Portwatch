"""
Framework mapping for PortWatch.

Maps scan findings onto OWASP Top 10 (2021) categories. This is a pure
translation layer over findings PortWatch already detects -- no new
scanning capability, just credibility: "this maps to A05:2021".

Categories currently covered:
    A01:2021  Broken Access Control
    A02:2021  Cryptographic Failures
    A05:2021  Security Misconfiguration
    A06:2021  Vulnerable and Outdated Components
    A07:2021  Identification and Authentication Failures
"""

import re

DANGEROUS_METHOD_RE = re.compile(r"\b(PUT|DELETE|TRACE|CONNECT)\b", re.IGNORECASE)

# Ports that should never be reachable from an untrusted network.
EXPOSED_SERVICE_PORTS = {
    21,      # FTP
    23,      # Telnet
    1433,    # MSSQL
    3306,    # MySQL
    3389,    # RDP
    5432,    # PostgreSQL
    5900,    # VNC
    6379,    # Redis
    27017,   # MongoDB
}

CATEGORIES = {
    "A01:2021": {"name": "Broken Access Control"},
    "A02:2021": {"name": "Cryptographic Failures"},
    "A05:2021": {"name": "Security Misconfiguration"},
    "A06:2021": {"name": "Vulnerable and Outdated Components"},
    "A07:2021": {"name": "Identification and Authentication Failures"},
}


def _script_output(port, name):
    out = port.get("scripts", {}).get(name, "")
    return out if isinstance(out, str) else ""


def generate_compliance_tags(ports, credential_checks=None):
    """
    Returns a list of:
        {"category": "A05:2021", "name": "Security Misconfiguration",
         "evidence": ["..."]}
    sorted by category id. Empty list when nothing maps.
    credential_checks is the opt-in findings dict (optional).
    """
    evidence = {cat: [] for cat in CATEGORIES}

    for p in ports:
        if p.get("state") != "open":
            continue
        port_num = p.get("port")

        for name, out in p.get("scripts", {}).items():
            if not isinstance(out, str) or not out:
                continue
            if name.startswith("http-vuln-") and "VULNERABLE" in out.upper():
                evidence["A06:2021"].append(f"Port {port_num}: {name} reported VULNERABLE")

        cipher_out = _script_output(p, "ssl-enum-ciphers").lower()
        if cipher_out and any(w in cipher_out for w in ("weak", "rc4", "3des", "des-cbc", "export")):
            evidence["A02:2021"].append(f"Port {port_num}: weak/legacy cipher suites offered")

        dh_out = _script_output(p, "ssl-dh-params").lower()
        if dh_out and any(w in dh_out for w in ("logjam", "vulnerable", "weak")):
            evidence["A02:2021"].append(f"Port {port_num}: weak Diffie-Hellman parameters (Logjam risk)")

        headers_out = _script_output(p, "http-security-headers")
        if headers_out and "missing" in headers_out.lower():
            missing = [
                h for h in (
                    "Content-Security-Policy", "Strict-Transport-Security",
                    "X-Frame-Options", "X-Content-Type-Options",
                    "Referrer-Policy", "Permissions-Policy",
                ) if h.lower() in headers_out.lower()
            ]
            if missing:
                evidence["A05:2021"].append(
                    f"Port {port_num}: missing security header(s): {', '.join(missing)}"
                )

        methods_out = _script_output(p, "http-methods")
        match = DANGEROUS_METHOD_RE.search(methods_out) if methods_out else None
        if match:
            evidence["A01:2021"].append(
                f"Port {port_num}: dangerous HTTP method allowed ({match.group(0).upper()})"
            )

        if port_num in EXPOSED_SERVICE_PORTS:
            service = p.get("service", "unknown")
            evidence["A05:2021"].append(
                f"Port {port_num} ({service}) exposed to the network"
            )

    cc = credential_checks or {}
    for f in cc.get("http_login_findings", []):
        if f.get("verdict") == "none_observed":
            evidence["A07:2021"].append(
                f"No rate limiting observed on login endpoint {f.get('url')} "
                f"after {f.get('attempts', '?')} failed attempts"
            )
    for d in cc.get("db_findings", []):
        if d.get("vulnerable"):
            evidence["A07:2021"].append(
                f"Port {d.get('port')}: {d.get('check')} — {d.get('detail')}"
            )

    tags = []
    for cat, items in evidence.items():
        if items:
            tags.append({
                "category": cat,
                "name": CATEGORIES[cat]["name"],
                "evidence": items,
            })
    tags.sort(key=lambda t: t["category"])
    return tags
