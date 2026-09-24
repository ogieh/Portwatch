"""
Audit log for PortWatch Pro.

A security product should be able to answer "who scanned what, and when".
record() appends one AuditLog row per notable event. Rows are never updated or
deleted by the application. Recording is best-effort: an audit failure is
logged and never breaks the action it describes.

Actions recorded (see callers):
  auth.register auth.login auth.login_failed auth.logout auth.logout_all
  auth.refresh auth.password_changed auth.reset_requested auth.reset_completed
  apikey.created apikey.revoked
  project.created project.updated project.deleted
  scan.requested scan.started scan.completed scan.failed scan.cancelled scan.deleted
  schedule.created schedule.updated schedule.deleted schedule.run
  channel.created channel.deleted
"""

from flask import current_app, has_request_context

from models.db import db, AuditLog


def record(action, user=None, resource=None, detail=None, ip=None, commit=True):
    """Append an audit row. `resource` is any model instance with an id."""
    try:
        if ip is None and has_request_context():
            from core.security import client_ip
            ip = client_ip()
        row = AuditLog(
            user_id=user.id if user is not None else None,
            actor=user.email if user is not None else None,
            action=action,
            resource_type=type(resource).__name__ if resource is not None else None,
            resource_id=getattr(resource, "id", None) if resource is not None else None,
            detail=(detail or "")[:2000] or None,
            ip=ip,
        )
        db.session.add(row)
        if commit:
            db.session.commit()
        return row
    except Exception as e:  # pragma: no cover - defensive
        try:
            db.session.rollback()
        except Exception:
            pass
        try:
            current_app.logger.warning("Audit record failed (%s): %s", action, e)
        except Exception:
            pass
        return None


def query_for(user, limit=100, action=None):
    """Own events for analysts; all events for admins."""
    q = AuditLog.query
    if user.role != "admin":
        q = q.filter(AuditLog.user_id == user.id)
    if action:
        q = q.filter(AuditLog.action.like(f"{action}%"))
    return q.order_by(AuditLog.id.desc()).limit(min(max(limit, 1), 500)).all()
