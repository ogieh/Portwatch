"""
Background scheduler for PortWatch Pro.

A single APScheduler background job wakes every N seconds, finds any enabled
Schedule whose next_run is due, and queues each one through the same
scan_service.request_scan() + scan_jobs.submit() path that manual scans use.
Each schedule is wrapped so one failing schedule never stops the others, and
the app context is pushed explicitly (APScheduler runs off the request thread,
so there is no ambient Flask context).

A schedule created before the authorisation gate existed (authorised=False)
is skipped and disabled rather than run: consent is recorded per schedule and
never assumed.
"""

from config import utcnow
from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler

_scheduler = None


def _run_due_schedules(app):
    with app.app_context():
        from models.db import db, Schedule, Project
        import scan_service
        import scan_jobs
        import audit

        now = utcnow()
        due = (
            Schedule.query.filter(
                Schedule.enabled.is_(True),
                Schedule.next_run <= now,
            ).all()
        )
        for sched in due:
            project = db.session.get(Project, sched.project_id)
            if project is None:
                # Orphaned schedule (project deleted): disable it.
                sched.enabled = False
                db.session.commit()
                continue
            if not sched.authorised:
                sched.enabled = False
                db.session.commit()
                audit.record("schedule.updated", resource=sched,
                             detail="disabled: no recorded authorisation")
                app.logger.warning("Schedule %s disabled: no recorded authorisation", sched.id)
                continue
            try:
                row = scan_service.request_scan(
                    project, sched.target, profile=sched.profile,
                    credential_checks=sched.credential_checks, trigger="scheduled",
                    authorised=True, requested_by=project.owner,
                )
                scan_jobs.submit(row.id)
                audit.record("schedule.run", user=project.owner, resource=sched,
                             detail=f"queued scan #{row.id} for {sched.target}")
                app.logger.info("Scheduled scan queued: schedule=%s target=%s scan=%s",
                                sched.id, sched.target, row.id)
            except Exception as e:  # pragma: no cover - defensive
                app.logger.warning("Scheduled scan failed (schedule=%s): %s", sched.id, e)
            finally:
                sched.last_run = now
                sched.next_run = now + timedelta(hours=sched.interval_hours)
                db.session.commit()
        db.session.remove()


def run_once(app):
    """Run one polling pass now (used by tests)."""
    _run_due_schedules(app)


def start(app):
    """Start the background scheduler bound to this app. Idempotent."""
    global _scheduler
    if _scheduler is not None:
        return _scheduler
    if not app.config.get("SCHEDULER_ENABLED", True):
        app.logger.info("Scheduler disabled by config.")
        return None

    poll = app.config.get("SCHEDULER_POLL_SECONDS", 30)
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        _run_due_schedules,
        "interval",
        seconds=poll,
        args=[app],
        id="portwatch_due_scans",
        max_instances=1,
        coalesce=True,
    )
    _scheduler.start()
    app.logger.info("Scheduler started (poll every %ss).", poll)
    return _scheduler
