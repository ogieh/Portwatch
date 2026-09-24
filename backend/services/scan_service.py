"""
Scan orchestration for PortWatch Pro.

Two halves, one path:

  request_scan()  validates scope + consent, creates a Scan row in status
                  "queued" and returns it. Cheap; safe to call in a request.
  execute_scan()  runs the engine for a queued row, applies the (preserved)
                  scoring and compliance layers, adds CVE intelligence,
                  persists the result, then fires notifications.

Manual scans, API-key scans, "run now" and the background scheduler all go
through request_scan() + scan_jobs.submit(); the job runner calls
execute_scan(). perform_scan() is the synchronous convenience (create and run
in one call) used by seed.py and by tests running in inline mode.
"""

from config import utcnow

from flask import current_app

from models.db import db, Scan, Project, User
import scanner
import scoring
import compliance
import cve_intel
import notifier
import audit

VALID_TRIGGERS = ("manual", "scheduled", "api")


class ScanRequestError(ValueError):
    """Bad input on a scan request (maps to HTTP 400/403 in the API)."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def validate_request(project, target, profile, authorised):
    """Raise ScanRequestError if the request must not proceed."""
    target = (target or "").strip()
    if not target:
        raise ScanRequestError("Target is required")
    if len(target) > 255 or any(c.isspace() for c in target):
        raise ScanRequestError("Target must be a single hostname or IP address")
    if profile not in scanner.SCAN_PROFILES:
        raise ScanRequestError(
            f"Unknown scan profile '{profile}'. Valid profiles: "
            f"{', '.join(sorted(scanner.SCAN_PROFILES))}"
        )
    if not authorised:
        raise ScanRequestError(
            "You must confirm you are authorised to scan this target", status=403
        )
    if not project.target_allowed(target):
        raise ScanRequestError(
            f"'{target}' is not in this project's allowed targets. Add it to the "
            f"project scope first.", status=403
        )
    return target


def request_scan(project, target, profile="standard", credential_checks=False,
                 trigger="manual", authorised=False, requested_by=None):
    """Validate and persist a queued Scan. Returns the row (committed)."""
    if trigger not in VALID_TRIGGERS:
        trigger = "manual"
    target = validate_request(project, target, profile, authorised)
    row = Scan(
        project_id=project.id,
        target=target,
        profile=profile,
        timestamp=utcnow(),
        trigger=trigger,
        status="queued",
        authorised=True,
        credential_checks=bool(credential_checks),
        requested_by=requested_by.id if requested_by is not None else None,
        full_data="{}",
    )
    db.session.add(row)
    db.session.commit()
    audit.record("scan.requested", user=requested_by, resource=row,
                 detail=f"{target} [{profile}] trigger={trigger}"
                        f"{' +credential_checks' if credential_checks else ''}")
    return row


def _enrich(scan_result):
    cc = scan_result.get("credential_checks")
    scan_result["risk"] = scoring.compute_risk(scan_result["ports"], cc)
    scan_result["compliance"] = compliance.generate_compliance_tags(scan_result["ports"], cc)
    scan_result["intel"] = cve_intel.enrich(scan_result["ports"], cc)
    scan_result["intel_summary"] = cve_intel.summarize(scan_result["intel"])
    return scan_result


def execute_scan(scan_id, cancel_check=None):
    """
    Run a queued scan to completion inside the current app context.
    Returns the Scan row in its final state. Never raises for engine errors;
    those are recorded on the row as status=failed.
    """
    row = db.session.get(Scan, scan_id)
    if row is None:
        return None
    if row.status == "cancelled":
        return row
    if row.status != "queued":
        return row

    row.status = "running"
    row.started_at = utcnow()
    db.session.commit()
    actor = db.session.get(User, row.requested_by) if row.requested_by else None
    audit.record("scan.started", user=actor, resource=row, detail=row.target)

    cfg = current_app.config
    simulate = cfg.get("SIMULATE_SCANS") or None
    project = db.session.get(Project, row.project_id)

    try:
        result = scanner.run_scan(
            row.target, profile=row.profile,
            credential_checks=row.credential_checks,
            simulate=simulate,
            scan_type=cfg.get("NMAP_SCAN_TYPE", "connect"),
            cancel_check=cancel_check,
        )
        result = _enrich(result)
    except scanner.ScanCancelled as e:
        db.session.refresh(row)
        if row.is_active():
            _finish(row, "cancelled", error=str(e))
            audit.record("scan.cancelled", user=actor, resource=row, detail=str(e))
        return row
    except Exception as e:
        db.session.refresh(row)
        if row.is_active():
            _finish(row, "failed", error=f"{type(e).__name__}: {e}"[:2000])
            audit.record("scan.failed", user=actor, resource=row, detail=str(e)[:500])
        return row

    # A cancel or timeout may have landed while the engine was running. The
    # row was already finalised by whoever did that; never overwrite it.
    db.session.refresh(row)
    if not row.is_active():
        return row
    if cancel_check and cancel_check():
        _finish(row, "cancelled", error="Scan cancelled by user")
        audit.record("scan.cancelled", user=actor, resource=row)
        return row

    risk = result["risk"]
    row.summary = result.get("summary", "")
    row.risk_score = risk.get("score")
    row.risk_grade = risk.get("grade")
    row.set_full(result)
    _finish(row, "completed")
    audit.record("scan.completed", user=actor, resource=row,
                 detail=f"{row.target} grade={row.risk_grade} score={row.risk_score} "
                        f"engine={result.get('engine')}")

    # Fire alerts (never allowed to break a scan).
    try:
        if project is not None:
            notifier.on_scan_complete(project, row)
    except Exception as e:  # pragma: no cover - defensive
        current_app.logger.warning("Notification dispatch failed: %s", e)

    return row


def _finish(row, status, error=None):
    row.status = status
    row.error = error
    row.finished_at = utcnow()
    db.session.commit()


def mark_timed_out(scan_id, seconds):
    row = db.session.get(Scan, scan_id)
    if row is not None and row.is_active():
        _finish(row, "failed", error=f"Scan exceeded the {seconds}s ceiling for the "
                                     f"'{row.profile}' profile and was stopped")
        actor = db.session.get(User, row.requested_by) if row.requested_by else None
        audit.record("scan.failed", user=actor, resource=row, detail="timed out")
    return row


def cancel_scan(row, user=None):
    """Mark a queued/running scan cancelled. The runner stops it at the next
    phase boundary and discards the result."""
    if not row.is_active():
        return False
    _finish(row, "cancelled", error="Scan cancelled by user")
    audit.record("scan.cancelled", user=user, resource=row, detail=row.target)
    return True


def perform_scan(project, target, profile="standard", credential_checks=False,
                 trigger="manual", authorised=True, requested_by=None):
    """Synchronous convenience: request + execute in the current thread."""
    row = request_scan(project, target, profile=profile,
                       credential_checks=credential_checks, trigger=trigger,
                       authorised=authorised, requested_by=requested_by)
    return execute_scan(row.id)


def list_profiles():
    cfg = current_app.config.get("SCAN_MAX_SECONDS", {})
    return {
        key: {
            "label": p["label"],
            "description": p["description"],
            "max_seconds": cfg.get(key),
        }
        for key, p in scanner.SCAN_PROFILES.items()
    }
