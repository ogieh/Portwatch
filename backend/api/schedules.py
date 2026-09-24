"""Schedules API: recurring-scan CRUD, scoped to the authenticated user."""

from config import utcnow
from datetime import datetime, timedelta

from flask import Blueprint, request, jsonify, g

from models.db import db, Project, Schedule
from core.security import require_auth
import scanner
import audit

bp = Blueprint("schedules", __name__, url_prefix="/api/schedules")

MIN_INTERVAL = 1     # hours
MAX_INTERVAL = 24 * 30


def _owned(schedule_id):
    return Schedule.query.filter_by(id=schedule_id, user_id=g.user.id).first()


@bp.route("", methods=["GET"])
@require_auth
def list_schedules():
    rows = (
        Schedule.query.filter_by(user_id=g.user.id)
        .order_by(Schedule.created_at.desc())
        .all()
    )
    return jsonify([s.to_dict() for s in rows])


@bp.route("", methods=["POST"])
@require_auth
def create_schedule():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    project_id = data.get("project_id")
    profile = data.get("profile") or "standard"
    interval = int(data.get("interval_hours") or 24)
    credential_checks = bool(data.get("credential_checks"))
    authorised = bool(data.get("authorised"))

    if not target:
        return jsonify({"error": "Target is required"}), 400
    if any(c.isspace() for c in target) or len(target) > 255:
        return jsonify({"error": "Target must be a single hostname or IP address"}), 400
    if not authorised:
        return jsonify({"error": "You must confirm you are authorised to scan this target"}), 403
    if profile not in scanner.SCAN_PROFILES:
        return jsonify({"error": f"Unknown profile '{profile}'"}), 400
    if not (MIN_INTERVAL <= interval <= MAX_INTERVAL):
        return jsonify({"error": f"Interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} hours"}), 400

    project = Project.query.filter_by(id=project_id, user_id=g.user.id).first()
    if project is None:
        return jsonify({"error": "Project not found"}), 404
    if not project.target_allowed(target):
        return jsonify({"error": f"'{target}' is not in this project's allowed targets"}), 403

    schedule = Schedule(
        user_id=g.user.id,
        project_id=project.id,
        target=target,
        profile=profile,
        credential_checks=credential_checks,
        interval_hours=interval,
        enabled=True,
        authorised=True,
        next_run=utcnow() + timedelta(hours=interval),
    )
    db.session.add(schedule)
    db.session.commit()
    audit.record("schedule.created", user=g.user, resource=schedule,
                 detail=f"{target} [{profile}] every {interval}h")
    return jsonify(schedule.to_dict()), 201


@bp.route("/<int:schedule_id>", methods=["PATCH"])
@require_auth
def update_schedule(schedule_id):
    schedule = _owned(schedule_id)
    if schedule is None:
        return jsonify({"error": "Schedule not found"}), 404
    data = request.get_json(silent=True) or {}

    if "enabled" in data:
        schedule.enabled = bool(data["enabled"])
    if "interval_hours" in data:
        interval = int(data["interval_hours"])
        if not (MIN_INTERVAL <= interval <= MAX_INTERVAL):
            return jsonify({"error": f"Interval must be between {MIN_INTERVAL} and {MAX_INTERVAL} hours"}), 400
        schedule.interval_hours = interval
        schedule.next_run = utcnow() + timedelta(hours=interval)
    if "profile" in data and data["profile"] in scanner.SCAN_PROFILES:
        schedule.profile = data["profile"]
    if "credential_checks" in data:
        schedule.credential_checks = bool(data["credential_checks"])
    if data.get("authorised") is True:
        schedule.authorised = True

    db.session.commit()
    audit.record("schedule.updated", user=g.user, resource=schedule,
                 detail=", ".join(sorted(k for k in data.keys()))[:200])
    return jsonify(schedule.to_dict())


@bp.route("/<int:schedule_id>", methods=["DELETE"])
@require_auth
def delete_schedule(schedule_id):
    schedule = _owned(schedule_id)
    if schedule is None:
        return jsonify({"error": "Schedule not found"}), 404
    target = schedule.target
    db.session.delete(schedule)
    db.session.commit()
    audit.record("schedule.deleted", user=g.user, detail=f"schedule #{schedule_id} {target}")
    return jsonify({"status": "deleted", "id": schedule_id})


@bp.route("/<int:schedule_id>/run", methods=["POST"])
@require_auth
def run_now(schedule_id):
    """Trigger a scheduled scan immediately (bumps next_run forward)."""
    schedule = _owned(schedule_id)
    if schedule is None:
        return jsonify({"error": "Schedule not found"}), 404

    import scan_service
    import scan_jobs
    from models.db import Scan
    if not schedule.authorised:
        return jsonify({"error": "This schedule has no recorded authorisation. Edit it and "
                                 "confirm you are authorised to scan the target."}), 403
    project = db.session.get(Project, schedule.project_id)
    if project is None:
        return jsonify({"error": "Project no longer exists"}), 404
    try:
        row = scan_service.request_scan(
            project, schedule.target, profile=schedule.profile,
            credential_checks=schedule.credential_checks, trigger="scheduled",
            authorised=True, requested_by=g.user,
        )
        scan_jobs.submit(row.id)
    except scan_service.ScanRequestError as e:
        return jsonify({"error": str(e)}), e.status
    except Exception as e:
        return jsonify({"error": f"Scan failed: {e}"}), 500

    schedule.last_run = utcnow()
    schedule.next_run = utcnow() + timedelta(hours=schedule.interval_hours)
    db.session.commit()
    audit.record("schedule.run", user=g.user, resource=schedule, detail=f"queued scan #{row.id}")
    row = db.session.get(Scan, row.id)
    return jsonify({"scan": row.to_summary(), "schedule": schedule.to_dict()}), 202 if row.is_active() else 200
