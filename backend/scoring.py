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

# ---- Weights (points deducted from 100) ----
HIGH_RISK_PENALTY = 15        # per open high-risk port
MEDIUM_RISK_PENALTY = 7       # per open medium-risk port
LOW_RISK_PENALTY = 2          # per other open port

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


def compute_risk(ports):
    """
    Returns {"score": int 0-100, "grade": str, "breakdown": [...]}
    where breakdown lists every deduction so the score is auditable.
    """
    breakdown = []
    open_ports = [p for p in ports if p.get("state") == "open"]

    high = [p for p in open_ports if p.get("risk") == "high"]
    medium = [p for p in open_ports if p.get("risk") == "medium"]
    low = [p for p in open_ports if p.get("risk") not in ("high", "medium")]

    def add(reason, count, weight):
        if count > 0:
            breakdown.append({"reason": reason, "points": -count * weight})

    add(f"{len(high)} high-risk open port(s)", len(high), HIGH_RISK_PENALTY)
    add(f"{len(medium)} medium-risk open port(s)", len(medium), MEDIUM_RISK_PENALTY)
    add(f"{len(low)} other open port(s)", len(low), LOW_RISK_PENALTY)

    vuln_count = 0
    weak_cipher_ports = 0
    weak_dh_ports = 0
    header_hits = 0
    method_ports = 0

    for p in open_ports:
        for name, out in p.get("scripts", {}).items():
            if isinstance(out, str) and out and name.startswith("http-vuln-") \
                    and "VULNERABLE" in out.upper():
                vuln_count += 1

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

    score = max(0, min(100, 100 - total_deducted))

    return {"score": score, "grade": grade_for_score(score), "breakdown": breakdown}
