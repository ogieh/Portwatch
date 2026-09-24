"""
Scan comparison for PortWatch.

Compares two stored scans of the same target and reports exactly what
changed: ports opened, ports closed, service/version changes, and the
risk-score movement. Pure post-processing over stored scan JSON -- the
scan engine is never involved.
"""

import re

_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
_TRAILING_RE = re.compile(r"[/?#].*$")


def normalize_target(target):
    """Reduce a target string so 'http://Example.com/' == 'example.com'."""
    t = (target or "").strip().lower()
    t = _SCHEME_RE.sub("", t)
    t = _TRAILING_RE.sub("", t)
    return t


def build_diff(before, after):
    """
    before/after are full scan records (as returned by get_scan_by_id).
    Raises ValueError when the targets don't match.

    Returns:
    {
      "target": str,
      "before": {id, timestamp, profile, risk_score, risk_grade},
      "after":  {...},
      "score_delta": int | None,
      "grade_change": {"from": "B", "to": "A"} | None,
      "profile_mismatch": bool,
      "opened_ports":  [{port, service, version, risk}],
      "closed_ports":  [{port, service, version, risk}],
      "changed_ports": [{port, from: {...}, to: {...}, version_changed}],
    }
    """
    target_before = normalize_target(before.get("target"))
    target_after = normalize_target(after.get("target"))
    if target_before != target_after:
        raise ValueError(
            f"Cannot compare scans of different targets: "
            f"'{before.get('target')}' vs '{after.get('target')}'"
        )

    def open_map(scan):
        return {
            p["port"]: p
            for p in scan.get("ports", [])
            if p.get("state") == "open"
        }

    before_ports = open_map(before)
    after_ports = open_map(after)

    opened = sorted(set(after_ports) - set(before_ports))
    closed = sorted(set(before_ports) - set(after_ports))
    common = sorted(set(before_ports) & set(after_ports))

    changed = []
    for port in common:
        b, a = before_ports[port], after_ports[port]
        if b.get("version") != a.get("version") or b.get("service") != a.get("service"):
            changed.append({
                "port": port,
                "from": {"service": b.get("service"), "version": b.get("version")},
                "to": {"service": a.get("service"), "version": a.get("version")},
                "version_changed": b.get("version") != a.get("version"),
            })

    def meta(scan):
        return {
            "id": scan.get("id"),
            "timestamp": scan.get("timestamp"),
            "profile": scan.get("profile") or "standard",
            "risk_score": (scan.get("risk") or {}).get("score"),
            "risk_grade": (scan.get("risk") or {}).get("grade"),
        }

    b_meta, a_meta = meta(before), meta(after)

    score_delta = None
    grade_change = None
    if b_meta["risk_score"] is not None and a_meta["risk_score"] is not None:
        score_delta = a_meta["risk_score"] - b_meta["risk_score"]
    if b_meta["risk_grade"] and a_meta["risk_grade"] and b_meta["risk_grade"] != a_meta["risk_grade"]:
        grade_change = {"from": b_meta["risk_grade"], "to": a_meta["risk_grade"]}

    return {
        "target": before.get("target"),
        "before": b_meta,
        "after": a_meta,
        "score_delta": score_delta,
        "grade_change": grade_change,
        "profile_mismatch": b_meta["profile"] != a_meta["profile"],
        "opened_ports": [
            {
                "port": p,
                "service": after_ports[p].get("service"),
                "version": after_ports[p].get("version"),
                "risk": after_ports[p].get("risk"),
            }
            for p in opened
        ],
        "closed_ports": [
            {
                "port": p,
                "service": before_ports[p].get("service"),
                "version": before_ports[p].get("version"),
                "risk": before_ports[p].get("risk"),
            }
            for p in closed
        ],
        "changed_ports": changed,
    }
