"""
Risk scoring for PortWatch.

Deterministic and explainable: every scan starts at 100 and loses points
for each finding, with fixed weights. The number shown on screen can
always be justified line-by-line in a client conversation.

Score bands:
    A >= 90    B >= 75    C >= 60    D >= 40    F < 40

Note: "quick" profile scans skip NSE scripts entirely, so their score can
only see port-level exposure. Compare scores between scans of the same
profile (the diff feature warns about profile mismatches).
"""

import re

# ---- Per-service criticality (points deducted from 100 per OPEN port) ----
# The score is a RANK of exposure, so the weights are ordered by how much an
# analyst weighs each exposed service, not by a single "high/medium/low" bucket.
# This ordering is what lets the score agree with expert severity ranking (see
# tests/ground_truth: replacing the old 3-bucket model with this table removed
# all 7 rank inversions). Crown-jewel data stores are heaviest; cleartext and
# remote-admin next; web and DNS lightest. Ports not listed get DEFAULT.
SERVICE_CRITICALITY = {
    # Exposed data stores (an open, reachable datastore is the worst case).
    6379: 22,   # Redis (frequently unauthenticated)
    1521: 20,   # Oracle DB
    27017: 20,  # MongoDB
    9200: 18,   # Elasticsearch
    3306: 18,   # MySQL
    5432: 18,   # PostgreSQL
    1433: 18,   # MSSQL
    11211: 16,  # memcached
    # Cleartext / remote administration.
    23: 20,     # Telnet (cleartext credentials)
    445: 16,    # SMB
    5900: 16,   # VNC
    3389: 16,   # RDP
    139: 12,    # NetBIOS session
    135: 8,     # MSRPC
    # Legacy / mail / shell.
    21: 10,     # FTP
    110: 7,     # POP3
    143: 7,     # IMAP
    25: 6,      # SMTP
    22: 6,      # SSH
    # Web / DNS (exposure expected, lightest weight).
    80: 3, 8080: 3, 443: 2, 8443: 2, 53: 2,
}
DEFAULT_CRITICALITY = 4       # any other open port

# Criticality tiers, used only to group the auditable breakdown by severity.
def _criticality_tier(weight):
    if weight >= 16:
        return "critical-exposure"
    if weight >= 10:
        return "high-exposure"
    if weight >= 6:
        return "elevated-exposure"
    return "standard-exposure"


_TIER_ORDER = ["critical-exposure", "high-exposure", "elevated-exposure", "standard-exposure"]

VULN_SCRIPT_PENALTY = 20      # per http-vuln-* script reporting VULNERABLE
VULN_SCRIPT_CAP = 40
WEAK_CIPHER_PENALTY = 10      # per port where ssl-enum-ciphers looks weak
WEAK_CIPHER_CAP = 20
WEAK_DH_PENALTY = 5           # per port where ssl-dh-params looks weak
WEAK_DH_CAP = 10
MISSING_HEADER_PENALTY = 3    # per missing security header per port
MISSING_HEADER_CAP = 12
DANGEROUS_METHOD_PENALTY = 6  # per port allowing PUT/DELETE/TRACE/CONNECT
DANGEROUS_METHOD_CAP = 12

FTP_ANON_PENALTY = 8          # per port where ftp-anon reports anonymous login allowed
FTP_ANON_CAP = 8
SMB_VULN_PENALTY = 20         # per smb-vuln-* script reporting VULNERABLE
SMB_VULN_CAP = 30

LOGIN_NO_THROTTLE_PENALTY = 12  # per login endpoint with no observed rate limit
LOGIN_NO_THROTTLE_CAP = 24
DB_AUTH_PENALTY = 20            # per DB auth failure (empty password / cracked creds)
DB_AUTH_CAP = 40

NUCLEI_SEVERITY_PENALTY = {"critical": 25, "high": 18, "medium": 8, "low": 3, "info": 0}
NUCLEI_PENALTY_CAP = 45

GRADE_BANDS = [
    (90, "A"),
    (75, "B"),
    (60, "C"),
    (40, "D"),
    (0, "F"),
]

KNOWN_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

DANGEROUS_METHOD_RE = re.compile(r"\b(PUT|DELETE|TRACE|CONNECT)\b", re.IGNORECASE)
WEAK_CIPHER_WORDS = ("weak", "rc4", "3des", "des-cbc", "export")
WEAK_DH_WORDS = ("logjam", "vulnerable", "weak")


def grade_for_score(score):
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def _script_output(port, name):
    out = port.get("scripts", {}).get(name, "")
    return out if isinstance(out, str) else ""


def compute_risk(ports, credential_checks=None, nuclei=None):
    """
    Returns {"score": int 0-100, "grade": str, "breakdown": [...]}
    where breakdown lists every deduction so the score is auditable.
    credential_checks is the opt-in findings dict from authtest (optional).
    """
    breakdown = []
    open_ports = [p for p in ports if p.get("state") == "open"]

    # Per-service criticality, grouped into tiers for an auditable breakdown.
    # Each open port deducts SERVICE_CRITICALITY[port] (or DEFAULT), and the
    # breakdown shows one line per tier listing exactly which ports it covers,
    # so the number on screen is still justifiable port by port.
    tiers = {t: {"ports": [], "points": 0} for t in _TIER_ORDER}
    for p in open_ports:
        weight = SERVICE_CRITICALITY.get(p.get("port"), DEFAULT_CRITICALITY)
        tier = _criticality_tier(weight)
        tiers[tier]["ports"].append(p.get("port"))
        tiers[tier]["points"] += weight

    for tier in _TIER_ORDER:
        info = tiers[tier]
        if info["points"] > 0:
            port_list = ", ".join(str(pp) for pp in sorted(info["ports"]))
            breakdown.append({
                "reason": f"{len(info['ports'])} {tier} service(s) open (ports: {port_list})",
                "points": -info["points"],
            })

    vuln_count = 0
    weak_cipher_ports = 0
    weak_dh_ports = 0
    header_hits = 0
    method_ports = 0
    ftp_anon_ports = 0
    smb_vuln_count = 0

    for p in open_ports:
        for name, out in p.get("scripts", {}).items():
            if isinstance(out, str) and out and name.startswith("http-vuln-") \
                    and "VULNERABLE" in out.upper():
                vuln_count += 1

        for name, out in p.get("scripts", {}).items():
            if isinstance(out, str) and name.startswith("smb-vuln-")                     and "VULNERABLE" in out.upper() and "NOT VULNERABLE" not in out.upper():
                smb_vuln_count += 1

        if "anonymous ftp login allowed" in _script_output(p, "ftp-anon").lower():
            ftp_anon_ports += 1

        cipher_out = _script_output(p, "ssl-enum-ciphers").lower()
        if cipher_out and any(w in cipher_out for w in WEAK_CIPHER_WORDS):
            weak_cipher_ports += 1

        dh_out = _script_output(p, "ssl-dh-params").lower()
        if dh_out and any(w in dh_out for w in WEAK_DH_WORDS):
            weak_dh_ports += 1

        headers_out = _script_output(p, "http-security-headers")
        if headers_out and "missing" in headers_out.lower():
            for h in KNOWN_SECURITY_HEADERS:
                if h.lower() in headers_out.lower():
                    header_hits += 1

        methods_out = _script_output(p, "http-methods")
        if methods_out and DANGEROUS_METHOD_RE.search(methods_out):
            method_ports += 1

    def add_capped(reason, total_points, cap):
        applied = min(total_points, cap)
        if applied > 0:
            breakdown.append({"reason": reason, "points": -applied})
            return applied
        return 0

    total_deducted = -sum(item["points"] for item in breakdown)

    total_deducted += add_capped(
        f"{vuln_count} vulnerable script hit(s)",
        vuln_count * VULN_SCRIPT_PENALTY, VULN_SCRIPT_CAP)
    total_deducted += add_capped(
        f"{weak_cipher_ports} port(s) with weak ciphers",
        weak_cipher_ports * WEAK_CIPHER_PENALTY, WEAK_CIPHER_CAP)
    total_deducted += add_capped(
        f"{weak_dh_ports} port(s) with weak DH params",
        weak_dh_ports * WEAK_DH_PENALTY, WEAK_DH_CAP)
    total_deducted += add_capped(
        f"{header_hits} missing security header(s)",
        header_hits * MISSING_HEADER_PENALTY, MISSING_HEADER_CAP)
    total_deducted += add_capped(
        f"{method_ports} port(s) with dangerous HTTP methods",
        method_ports * DANGEROUS_METHOD_PENALTY, DANGEROUS_METHOD_CAP)

    total_deducted += add_capped(
        f"{ftp_anon_ports} port(s) allowing anonymous FTP login",
        ftp_anon_ports * FTP_ANON_PENALTY, FTP_ANON_CAP)
    total_deducted += add_capped(
        f"{smb_vuln_count} vulnerable SMB script hit(s)",
        smb_vuln_count * SMB_VULN_PENALTY, SMB_VULN_CAP)

    # ---- Opt-in credential & lockout check deductions (A07 territory) ----
    cc = credential_checks or {}
    unprotected = [
        f for f in cc.get("http_login_findings", [])
        if f.get("verdict") == "none_observed"
    ]
    db_auth_failures = [
        d for d in cc.get("db_findings", []) if d.get("vulnerable")
    ]

    total_deducted += add_capped(
        f"{len(unprotected)} login endpoint(s) with no observed rate limiting",
        len(unprotected) * LOGIN_NO_THROTTLE_PENALTY, LOGIN_NO_THROTTLE_CAP)
    total_deducted += add_capped(
        f"{len(db_auth_failures)} database auth failure(s)",
        len(db_auth_failures) * DB_AUTH_PENALTY, DB_AUTH_CAP)

    # ---- Nuclei template findings, severity-weighted, one auditable line ----
    counts = {}
    nuclei_points = 0
    for f in nuclei or []:
        sev = str(f.get("severity", "")).lower()
        counts[sev] = counts.get(sev, 0) + 1
        nuclei_points += NUCLEI_SEVERITY_PENALTY.get(sev, 0)
    by_sev = ", ".join(f"{counts[s]} {s}" for s in NUCLEI_SEVERITY_PENALTY if s in counts)
    total_deducted += add_capped(
        f"{sum(counts.values())} nuclei finding(s) ({by_sev})",
        nuclei_points, NUCLEI_PENALTY_CAP)

    score = max(0, min(100, 100 - total_deducted))

    return {"score": score, "grade": grade_for_score(score), "breakdown": breakdown}
