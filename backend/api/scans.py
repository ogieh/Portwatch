"""Scans API: submit (async) / status / list / detail / cancel / diff / report / delete.

POST /api/scan returns 202 with the queued scan; poll GET /api/scans/<id>
until `status` is completed, failed or cancelled. Pass ?wait=1 on POST to
block for up to 25 seconds (handy for scripts and API-key use).
"""

import time

from flask import Blueprint, request, jsonify, g, Response, current_app

from models.db import db, Project, Scan
from core.security import require_auth
from core.ratelimit import rate_limit
import scan_service
import scan_jobs
import diffing
import audit
import report as report_mod

bp = Blueprint("scans", __name__, url_prefix="/api")

WAIT_MAX_SECONDS = 25


def _owned_project(project_id):
    return Project.query.filter_by(id=project_id, user_id=g.user.id).first()


def _owned_scan(scan_id):
    return (
        Scan.query.join(Project)
        .filter(Scan.id == scan_id, Project.user_id == g.user.id)
        .first()
    )


@bp.route("/profiles", methods=["GET"])
@require_auth
def profiles():
    return jsonify(scan_service.list_profiles())


@bp.route("/scan", methods=["POST"])
@require_auth
@rate_limit("RATELIMIT_SCAN", name="scan")
def run_scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    project_id = data.get("project_id")
    profile = data.get("profile") or "standard"
    credential_checks = bool(data.get("credential_checks"))
    authorised = bool(data.get("authorised"))
    wait = request.args.get("wait", data.get("wait")) in ("1", "true", True)

    if not project_id:
        return jsonify({"error": "A project_id is required"}), 400
    project = _owned_project(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404

    trigger = "api" if g.auth_kind == "api_key" else "manual"
    try:
        row = scan_service.request_scan(
            project, target, profile=profile, credential_checks=credential_checks,
            trigger=trigger, authorised=authorised, requested_by=g.user,
        )
    except scan_service.ScanRequestError as e:
        return jsonify({"error": str(e)}), e.status
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    scan_id = row.id
    try:
        scan_jobs.submit(scan_id)
    except Exception as e:  # pragma: no cover - defensive
        scan_service.cancel_scan(row)
        return jsonify({"error": f"Could not queue scan: {e}"}), 500

    db.session.expire_all()
    row = db.session.get(Scan, scan_id)
    if wait:
        deadline = time.monotonic() + WAIT_MAX_SECONDS
        while row.is_active() and time.monotonic() < deadline:
            time.sleep(0.25)
            db.session.expire(row)
            row = db.session.get(Scan, scan_id)

    if row.is_active():
        return jsonify(row.get_full()), 202
    return jsonify(row.get_full()), 200


@bp.route("/scans", methods=["GET"])
@require_auth
def list_scans():
    """All scans for the user, newest first. Optional ?project_id= and ?status= filters."""
    query = Scan.query.join(Project).filter(Project.user_id == g.user.id)
    project_id = request.args.get("project_id", type=int)
    if project_id:
        query = query.filter(Scan.project_id == project_id)
    status = request.args.get("status")
    if status:
        query = query.filter(Scan.status == status)
    limit = min(request.args.get("limit", 200, type=int), 1000)
    scans = query.order_by(Scan.id.desc()).limit(limit).all()
    return jsonify([s.to_summary() for s in scans])


@bp.route("/scans/<int:scan_id>", methods=["GET"])
@require_auth
def get_scan(scan_id):
    scan = _owned_scan(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan.get_full())


@bp.route("/scans/<int:scan_id>/cancel", methods=["POST"])
@require_auth
def cancel_scan(scan_id):
    scan = _owned_scan(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    if not scan.is_active():
        return jsonify({"error": f"Scan is already {scan.status}"}), 409
    scan_jobs.cancel(scan.id)
    scan_service.cancel_scan(scan, user=g.user)
    return jsonify(scan.to_summary())


@bp.route("/scans/<int:scan_id>", methods=["DELETE"])
@require_auth
def delete_scan(scan_id):
    scan = _owned_scan(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    if scan.is_active():
        return jsonify({"error": "Cancel the scan before deleting it"}), 409
    detail = f"{scan.target} [{scan.profile}]"
    db.session.delete(scan)
    db.session.commit()
    audit.record("scan.deleted", user=g.user, detail=f"scan #{scan_id} {detail}")
    return jsonify({"status": "deleted", "id": scan_id})


@bp.route("/scans/<int:before_id>/diff/<int:after_id>", methods=["GET"])
@require_auth
def diff_scans(before_id, after_id):
    before = _owned_scan(before_id)
    after = _owned_scan(after_id)
    if before is None or after is None:
        return jsonify({"error": "One or both scans were not found"}), 404
    if before.status != "completed" or after.status != "completed":
        return jsonify({"error": "Both scans must be completed to compare them"}), 400
    try:
        diff = diffing.build_diff(before.get_full(), after.get_full())
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if diff["profile_mismatch"]:
        diff["warning"] = (
            f"Profile mismatch: #{before_id} used '{diff['before']['profile']}' and "
            f"#{after_id} used '{diff['after']['profile']}'. Port and score "
            f"differences may just reflect the deeper scan, not a real change."
        )
    return jsonify(diff)


@bp.route("/scans/<int:scan_id>/report", methods=["GET"])
@require_auth
def scan_report(scan_id):
    scan = _owned_scan(scan_id)
    if scan is None:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != "completed":
        return jsonify({"error": f"No report: scan is {scan.status}"}), 400
    html = report_mod.build_report_html(scan.get_full(), project=scan.project)
    return Response(html, mimetype="text/html")
