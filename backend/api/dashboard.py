"""Dashboard API: aggregate KPIs and time-series for the authenticated user."""

from collections import defaultdict

from flask import Blueprint, jsonify, g

from models.db import Project, Scan
from core.security import require_auth
import cve_intel

bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


@bp.route("", methods=["GET"])
@require_auth
def dashboard():
    projects = Project.query.filter_by(user_id=g.user.id).all()
    scans = (
        Scan.query.join(Project)
        .filter(Project.user_id == g.user.id)
        .order_by(Scan.id.asc())
        .all()
    )

    graded = [s for s in scans if s.risk_score is not None]
    avg_score = round(sum(s.risk_score for s in graded) / len(graded)) if graded else None

    # Grade distribution across latest scan per project (current posture).
    latest_by_project = {}
    for s in scans:
        latest_by_project[s.project_id] = s  # asc order → last wins = newest
    grade_dist = defaultdict(int)
    for s in latest_by_project.values():
        if s.risk_grade:
            grade_dist[s.risk_grade] += 1

    # Aggregate open-finding severity across latest scans + count CVEs.
    sev_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    unique_cves = set()
    for s in latest_by_project.values():
        full = s.get_full()
        summ = full.get("intel_summary")
        if not summ:
            # older scans without intel: compute on the fly
            intel = cve_intel.enrich(full.get("ports", []), full.get("credential_checks"))
            summ = cve_intel.summarize(intel)
        for k, v in (summ.get("counts") or {}).items():
            sev_totals[k] = sev_totals.get(k, 0) + v
        unique_cves.update(summ.get("unique_cves") or [])

    # Score trend: last 20 scans chronologically.
    trend = [
        {
            "id": s.id,
            "timestamp": s.timestamp.isoformat() if s.timestamp else None,
            "score": s.risk_score,
            "grade": s.risk_grade,
            "target": s.target,
        }
        for s in graded[-20:]
    ]

    # Worst current exposures (highest-severity findings from latest scans).
    worst = []
    for s in latest_by_project.values():
        full = s.get_full()
        intel = full.get("intel") or cve_intel.enrich(
            full.get("ports", []), full.get("credential_checks")
        )
        for f in intel:
            if f["severity"] in ("critical", "high"):
                worst.append({
                    "project_id": s.project_id,
                    "scan_id": s.id,
                    "target": s.target,
                    "port": f["port"],
                    "severity": f["severity"],
                    "title": f["title"],
                    "cve": f.get("cve") or [],
                })
    worst.sort(key=lambda w: 0 if w["severity"] == "critical" else 1)

    return jsonify({
        "kpis": {
            "projects": len(projects),
            "total_scans": len(scans),
            "avg_score": avg_score,
            "critical_findings": sev_totals["critical"],
            "high_findings": sev_totals["high"],
            "unique_cves": len(unique_cves),
        },
        "grade_distribution": dict(grade_dist),
        "severity_totals": sev_totals,
        "score_trend": trend,
        "top_exposures": worst[:10],
        "recent_scans": [s.to_summary() for s in scans[::-1][:8]],
    })
