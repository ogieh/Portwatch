"""
Turns a finished scan record into structured, report-ready findings.

Each finding carries the pieces a client actually needs: what we saw,
why it matters, and concrete remediation steps. Severity follows the
usual pentest-report scale (critical / high / medium / low).

This module shares its detection patterns with scoring.py and
compliance.py (imported below) so the three never disagree about what
counts as "weak ciphers" etc.
"""

import re

from compliance import DANGEROUS_METHOD_RE
from scoring import (
    KNOWN_SECURITY_HEADERS,
    WEAK_CIPHER_WORDS,
    WEAK_DH_WORDS,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Database / remote-admin ports that should never face an untrusted network,
# mapped to their remediation angle.
EXPOSURE_ADVICE = {
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB",
}

PLAINTEXT_PORTS = {
    21: ("FTP transmits credentials and data in cleartext.",
         "Disable FTP and move transfers to SFTP or FTPS. If FTP must remain, "
         "restrict it to explicit internal clients and enforce TLS."),
    23: ("Telnet exposes a shell whose entire session, including credentials, "
         "is readable by anyone on the path.",
         "Disable Telnet entirely and administer the host over SSH (protocol 2 "
         "only) with key-based authentication."),
}


def _headers_missing(output):
    return [
        h for h in KNOWN_SECURITY_HEADERS
        if h.lower() in output.lower()
    ]


def build_findings(record):
    """
    Returns findings sorted by severity:
      [{"id": "PW-001", "severity": "high", "title": str,
        "description": str, "impact": str,
        "remediation": [str, ...], "evidence": [str, ...],
        "owasp": ["A05:2021"]}, ...]
    """
    open_ports = [p for p in record.get("ports", []) if p.get("state") == "open"]

    exposed_db = {}
    plaintext = {}
    vuln_hits = []
    weak_cipher_ports = []
    weak_dh_ports = []
    method_hits = []          # (port, verb)
    hsts_missing = []         # tls ports without HSTS
    hardening_missing = {}    # header name -> [ports]

    for p in open_ports:
        port_num = p.get("port")
        if port_num in EXPOSURE_ADVICE:
            exposed_db.setdefault(port_num, EXPOSURE_ADVICE[port_num])
        if port_num in PLAINTEXT_PORTS:
            plaintext[port_num] = PLAINTEXT_PORTS[port_num]

        for name, out in (p.get("scripts") or {}).items():
            if not isinstance(out, str) or not out:
                continue
            upper = out.upper()
            lower = out.lower()

            if name.startswith("http-vuln-") and "VULNERABLE" in upper:
                vuln_hits.append((port_num, name))

            if name == "ssl-enum-ciphers" and any(w in lower for w in WEAK_CIPHER_WORDS):
                weak_cipher_ports.append(port_num)

            if name == "ssl-dh-params" and any(w in lower for w in WEAK_DH_WORDS):
                weak_dh_ports.append(port_num)

            if name == "http-methods":
                m = DANGEROUS_METHOD_RE.search(out)
                if m:
                    method_hits.append((port_num, m.group(0).upper()))

            if name == "http-security-headers" and "missing" in lower:
                missing = _headers_missing(out)
                if "Strict-Transport-Security" in missing and port_num in (443, 8443):
                    hsts_missing.append(port_num)
                for h in missing:
                    if h == "Strict-Transport-Security":
                        continue
                    hardening_missing.setdefault(h, []).append(port_num)

    cc = record.get("credential_checks") or {}
    unprotected_logins = [
        f for f in cc.get("http_login_findings", [])
        if f.get("verdict") == "none_observed"
    ]
    db_auth_failures = [d for d in cc.get("db_findings", []) if d.get("vulnerable")]

    raw = []

    # ---- critical: confirmed weak authentication ----
    if db_auth_failures:
        ev = [f"Port {d['port']}: {d['check']} — {d['detail']}" for d in db_auth_failures]
        raw.append({
            "severity": "critical",
            "title": "Database services accept default or empty credentials",
            "description":
                "Credential checks against exposed database services succeeded "
                "without a valid username/password combination.",
            "impact":
                "An attacker can read, modify or destroy the data behind these "
                "services directly. This is the most commonly exploited class of "
                "internet-facing misconfiguration.",
            "remediation": [
                "Set strong, unique credentials on every database account immediately.",
                "Rotate any API keys, application passwords or secrets that used "
                "these services, and treat data reachable through them as potentially "
                "compromised.",
                "Remove public reachability of the ports listed below (see the "
                "exposed-services finding) so credentials are not the only control.",
            ],
            "evidence": ev,
            "owasp": ["A07:2021"],
        })

    # ---- high: exploitable software ----
    if vuln_hits:
        ev = [f"Port {p}: {name} reported VULNERABLE" for p, name in vuln_hits]
        raw.append({
            "severity": "high",
            "title": "Web endpoints matched known-vulnerability scripts",
            "description":
                "NSE vulnerability scripts flagged behaviour consistent with "
                "published CVEs on the affected endpoints.",
            "impact":
                "Public exploit code usually exists for these classes of issue; "
                "compromise typically requires nothing more than a single request.",
            "remediation": [
                "Identify the exact running version of the affected software and "
                "update to a release where the CVE is fixed.",
                "If patching must wait, apply a virtual patch (WAF rule or reverse-"
                "proxy block) for the specific request paths involved.",
                "Re-run this scan after remediation to confirm the flags clear.",
            ],
            "evidence": ev,
            "owasp": ["A06:2021"],
        })

    # ---- high: exposed admin/database surfaces ----
    if exposed_db:
        ev = [f"Port {p} ({svc}) answered openly" for p, svc in sorted(exposed_db.items())]
        raw.append({
            "severity": "high",
            "title": "Database and remote-administration ports are internet-reachable",
            "description":
                "Services intended for internal administration accept connections "
                "from the scanned network position.",
            "impact":
                "These services become the fastest route in: brute force, protocol "
                "vulnerabilities and stolen credentials all work without a foothold "
                "on the network first.",
            "remediation": [
                "Firewall each listed port to the specific hosts that legitimately "
                "need it; prefer a VPN or bastion for administrative access.",
                "Bind services to localhost or a private interface where remote "
                "access is not genuinely required.",
                "Where the product supports it, enable TLS and per-account login "
                "hardening (e.g. MySQL connection_control, Windows account policies "
                "for RDP, requirepass for Redis).",
            ],
            "evidence": ev,
            "owasp": ["A05:2021"],
        })

    # ---- high: plaintext protocols ----
    if plaintext:
        ev = [f"Port {p} open — {reason}" for p, (reason, _) in sorted(plaintext.items())]
        raw.append({
            "severity": "high",
            "title": "Cleartext management/file-transfer protocols in use",
            "description":
                "Protocols that carry credentials in the clear were reachable "
                "during the scan.",
            "impact":
                "Anyone positioned to observe traffic (shared network, ISP, "
                "compromised hop) captures working credentials outright.",
            "remediation": [fix for _, fix in sorted(plaintext.values())],
            "evidence": ev,
            "owasp": ["A02:2021"],
        })

    # ---- medium: authentication throttling absent ----
    if unprotected_logins:
        ev = [
            f"{f.get('url')} — {f.get('detail')}" for f in unprotected_logins
        ]
        raw.append({
            "severity": "medium",
            "title": "Login endpoints showed no rate limiting or lockout response",
            "description":
                "Repeated deliberately failed authentication attempts received "
                "identical, immediate failures with no throttle, CAPTCHA or "
                "lockout signal.",
            "impact":
                "Password spraying and brute force can proceed at full speed. "
                "Combined with weak password policy this frequently ends in "
                "account takeover.",
            "remediation": [
                "Return HTTP 429 with exponential backoff after repeated failures "
                "from the same source.",
                "Add temporary account lockout or progressive delay per account, "
                "tuned so it cannot be abused to deny service to real users.",
                "Alert on elevated failed-authentication volume; consider CAPTCHA "
                "as a last-resort friction layer.",
            ],
            "evidence": ev,
            "owasp": ["A07:2021"],
        })

    # ---- medium: tls quality ----
    if weak_cipher_ports or weak_dh_ports:
        parts = []
        if weak_cipher_ports:
            parts.append("weak/legacy cipher suites on ports " +
                         ", ".join(map(str, sorted(set(weak_cipher_ports)))))
        if weak_dh_ports:
            parts.append("weak Diffie-Hellman parameters on ports " +
                         ", ".join(map(str, sorted(set(weak_dh_ports)))))
        raw.append({
            "severity": "medium",
            "title": "Legacy TLS configuration detected",
            "description":
                "TLS handshakes offered cryptographic parameters considered weak "
                "by current standards: " + "; ".join(parts) + ".",
            "impact":
                "Downgrade and precomputation attacks against legacy crypto "
                "(Logjam-class) are practical for well-funded adversaries and "
                "automated for commodity ones.",
            "remediation": [
                "Disable TLS 1.0/1.1 and export-era suites (RC4, 3DES, EXPORT, "
                "single DES); serve TLS 1.2+ with AEAD suites only.",
                "Replace DH parameters shorter than 2048 bits, or prefer ECDHE "
                "groups.",
                "Validate with a scanner such as testssl.sh after changes.",
            ],
            "evidence": [f"Port {p}: {name}" for p, name in sorted(
                [(p, "ssl-enum-ciphers") for p in weak_cipher_ports] +
                [(p, "ssl-dh-params") for p in weak_dh_ports])],
            "owasp": ["A02:2021"],
        })

    # ---- medium: dangerous http verbs ----
    if method_hits:
        ev = [f"Port {p}: allows {v}" for p, v in method_hits]
        raw.append({
            "severity": "medium",
            "title": "Dangerous HTTP methods accepted",
            "description":
                "The surveyed endpoints advertise support for state-changing or "
                "debugging verbs (PUT/DELETE/TRACE/CONNECT).",
            "impact":
                "Unintended write access through forgotten VERB handling is a "
                "reliable escalation path when authorisation checks only guard "
                "GET/POST routes.",
            "remediation": [
                "Disable unused HTTP methods at the web server or framework "
                "router level.",
                "Ensure every state-changing method passes the same authorisation "
                "checks as POST routes.",
                "Disable TRACE specifically (cross-site tracing, XST).",
            ],
            "evidence": ev,
            "owasp": ["A01:2021"],
        })

    # ---- medium: HSTS ----
    if hsts_missing:
        ports_txt = ", ".join(str(p) for p in sorted(set(hsts_missing)))
        raw.append({
            "severity": "medium",
            "title": "HTTP Strict Transport Security not enforced",
            "description":
                f"HTTPS service on port(s) {ports_txt} did not return a "
                "Strict-Transport-Security header.",
            "impact":
                "The first request of every visitor session can be downgraded to "
                "cleartext by an intercepting attacker (SSL-stripping).",
            "remediation": [
                "Send 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains' once every subdomain reliably serves HTTPS.",
                "Consider preload submission after verifying long-term HTTPS "
                "coverage.",
            ],
            "evidence": [f"Port {p}: no HSTS header returned" for p in sorted(set(hsts_missing))],
            "owasp": ["A05:2021"],
        })

    # ---- low: remaining hardening headers ----
    if hardening_missing:
        ev = [
            f"{h} missing on port(s) " + ", ".join(map(str, sorted({*ports})))
            for h, ports in sorted(hardening_missing.items())
        ]
        raw.append({
            "severity": "low",
            "title": "Browser hardening headers absent",
            "description":
                "Several standard defence-in-depth headers were not returned by "
                "the scanned web services.",
            "impact":
                "Individually minor, together these headers remove cheap barriers "
                "against clickjacking, MIME confusion and script-injection "
                "blast radius.",
            "remediation": [
                "Content-Security-Policy: start in report-only mode, tighten to "
                "'default-src self' plus explicit allowances.",
                "X-Frame-Options: SAMEORIGIN (or frame-ancestors in CSP).",
                "X-Content-Type-Options: nosniff.",
                "Referrer-Policy: strict-origin-when-cross-origin.",
                "Permissions-Policy: disable unused browser features.",
            ],
            "evidence": ev,
            "owasp": ["A05:2021"],
        })

    # ---- assign sequential ids in severity order ----
    raw.sort(key=lambda f: SEVERITY_ORDER[f["severity"]])
    findings = []
    for i, f in enumerate(raw, start=1):
        f["id"] = f"PW-{i:03d}"
        findings.append(f)
    return findings


def passed_checks(record):
    """Things that were looked at and came back clean - included in the
    report because a clean bill of evidence builds trust in the rest."""
    checks = []
    open_ports = [p for p in record.get("ports", []) if p.get("state") == "open"]

    def any_script(prefix_frag):
        for p in open_ports:
            for name, out in (p.get("scripts") or {}).items():
                if isinstance(out, str) and prefix_frag(name, out):
                    return True
        return False

    # only claim the CVE scripts came back clean if they actually ran
    vuln_ran = any_script(lambda n, o: n.startswith("http-vuln-"))
    if vuln_ran and not any_script(
            lambda n, o: n.startswith("http-vuln-") and "VULNERABLE" in o.upper()):
        checks.append("Published-CVE web scripts (http-vuln-*) reported no matches.")

    had_tls_check = any_script(lambda n, o: n == "ssl-enum-ciphers")
    weak_re = re.compile("|".join(WEAK_CIPHER_WORDS))
    if had_tls_check:
        any_weak = any(
            weak_re.search(o.lower())
            for p in open_ports
            for n, o in (p.get("scripts") or {}).items()
            if n == "ssl-enum-ciphers"
        )
        if not any_weak:
            checks.append("TLS suites offered on scanned ports contained no obviously weak entries.")

    if not any(p.get("port") in EXPOSURE_ADVICE for p in open_ports):
        checks.append("No database or remote-administration ports were reachable.")

    cc = record.get("credential_checks") or {}
    logins = cc.get("http_login_findings") or []
    if cc.get("enabled") and logins:
        protected = all(f.get("verdict") != "none_observed" for f in logins)
        if protected:
            checks.append("Every discovered login endpoint applied throttling or lockout under repeated failures.")

    return checks
