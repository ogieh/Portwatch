"""
Database models for PortWatch Pro.

Relationships:
    User 1--* Project 1--* Scan
    User 1--* Schedule --1 Project
    User 1--* NotificationChannel
    User 1--* RefreshToken / PasswordResetToken / ApiKey
    User 1--* AuditLog (append-only)

The full original scan dict (ports, scripts, risk, compliance, credential_checks)
is stored verbatim in Scan.full_data as JSON, so every downstream consumer that
was written against the original shape keeps working untouched.

Schema changes are managed with Alembic (backend/migrations). When you change a
model here, add a migration; do not rely on create_all() for existing data.
"""

import hashlib
import json
import secrets

from core.config import utcnow

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

SCAN_STATUSES = ("queued", "running", "completed", "failed", "cancelled")


def hash_token(raw):
    """Opaque tokens (refresh, reset, API keys) are stored hashed, never raw."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="analyst")  # analyst | admin
    # Bumped on password change / "sign out everywhere"; embedded in every
    # access token so older tokens stop validating immediately.
    token_version = db.Column(db.Integer, nullable=False, default=0)
    password_changed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)

    projects = db.relationship("Project", backref="owner", cascade="all, delete-orphan")
    schedules = db.relationship("Schedule", backref="owner", cascade="all, delete-orphan")
    channels = db.relationship("NotificationChannel", backref="owner", cascade="all, delete-orphan")
    refresh_tokens = db.relationship("RefreshToken", backref="user", cascade="all, delete-orphan")
    reset_tokens = db.relationship("PasswordResetToken", backref="user", cascade="all, delete-orphan")
    api_keys = db.relationship("ApiKey", backref="user", cascade="all, delete-orphan")

    def set_password(self, raw):
        self.password_hash = generate_password_hash(raw)
        self.password_changed_at = utcnow()

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    def revoke_all_sessions(self):
        """Invalidate every access token and refresh token for this user."""
        self.token_version = (self.token_version or 0) + 1
        for rt in self.refresh_tokens:
            rt.revoked = True

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "password_changed_at": (
                self.password_changed_at.isoformat() if self.password_changed_at else None
            ),
        }


class Project(db.Model):
    __tablename__ = "projects"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, default="")
    # Optional scope allowlist: one target per line. When set, a scan target
    # must match an entry (exact host, or a *.suffix wildcard). Empty means the
    # project has no allowlist and only the per-scan consent applies.
    allowed_targets = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utcnow)

    scans = db.relationship(
        "Scan", backref="project", cascade="all, delete-orphan",
        order_by="Scan.id.desc()"
    )

    def allowlist(self):
        return [t.strip().lower() for t in (self.allowed_targets or "").splitlines() if t.strip()]

    def target_allowed(self, target):
        """True when the project has no allowlist or the target matches one."""
        entries = self.allowlist()
        if not entries:
            return True
        t = _normalize_target(target)
        for entry in entries:
            if entry.startswith("*."):
                suffix = entry[1:]  # ".example.com"
                if t == entry[2:] or t.endswith(suffix):
                    return True
            elif t == entry:
                return True
        return False

    def to_dict(self, with_stats=False):
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description or "",
            "allowed_targets": self.allowlist(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "scan_count": len(self.scans),
        }
        if with_stats:
            graded = [s for s in self.scans if s.risk_score is not None]
            latest = self.scans[0] if self.scans else None
            data["latest_scan"] = latest.to_summary() if latest else None
            data["avg_score"] = (
                round(sum(s.risk_score for s in graded) / len(graded)) if graded else None
            )
        return data


def _normalize_target(target):
    t = (target or "").strip().lower()
    for scheme in ("http://", "https://"):
        if t.startswith(scheme):
            t = t[len(scheme):]
    for sep in ("/", "?", "#"):
        t = t.split(sep, 1)[0]
    return t


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=False)
    profile = db.Column(db.String(20), nullable=False, default="standard")
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    summary = db.Column(db.Text, default="")
    risk_score = db.Column(db.Integer)
    risk_grade = db.Column(db.String(2))
    trigger = db.Column(db.String(20), default="manual")  # manual | scheduled | api
    full_data = db.Column(db.Text, nullable=False, default="{}")
    # Lifecycle for background execution.
    status = db.Column(db.String(20), nullable=False, default="completed", index=True)
    error = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    # Recorded consent: the requester confirmed they are authorised to scan.
    authorised = db.Column(db.Boolean, nullable=False, default=False)
    credential_checks = db.Column(db.Boolean, nullable=False, default=False)
    requested_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"))

    def set_full(self, data_dict):
        self.full_data = json.dumps(data_dict)

    def get_full(self):
        try:
            data = json.loads(self.full_data)
        except (TypeError, ValueError):
            data = {}
        data["id"] = self.id
        data["project_id"] = self.project_id
        data["trigger"] = self.trigger
        data["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        data["status"] = self.status
        data["error"] = self.error
        data["authorised"] = bool(self.authorised)
        data["duration_seconds"] = self.duration_seconds()
        data.setdefault("target", self.target)
        data.setdefault("profile", self.profile)
        return data

    def duration_seconds(self):
        if self.started_at and self.finished_at:
            return round((self.finished_at - self.started_at).total_seconds(), 1)
        return None

    def is_active(self):
        return self.status in ("queued", "running")

    def to_summary(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "target": self.target,
            "profile": self.profile,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "summary": self.summary,
            "risk_score": self.risk_score,
            "risk_grade": self.risk_grade,
            "trigger": self.trigger,
            "status": self.status,
            "error": self.error,
            "authorised": bool(self.authorised),
            "duration_seconds": self.duration_seconds(),
        }


class Schedule(db.Model):
    __tablename__ = "schedules"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    profile = db.Column(db.String(20), nullable=False, default="standard")
    credential_checks = db.Column(db.Boolean, default=False)
    interval_hours = db.Column(db.Integer, nullable=False, default=24)
    enabled = db.Column(db.Boolean, default=True)
    authorised = db.Column(db.Boolean, nullable=False, default=False)
    last_run = db.Column(db.DateTime)
    next_run = db.Column(db.DateTime, index=True)
    created_at = db.Column(db.DateTime, default=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "target": self.target,
            "profile": self.profile,
            "credential_checks": self.credential_checks,
            "interval_hours": self.interval_hours,
            "enabled": self.enabled,
            "authorised": bool(self.authorised),
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class NotificationChannel(db.Model):
    __tablename__ = "notification_channels"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    kind = db.Column(db.String(20), nullable=False)  # email | webhook
    target = db.Column(db.String(500), nullable=False)  # email address or webhook URL
    # Only alert when a scan's grade is at or below this threshold (F worst).
    min_grade = db.Column(db.String(2), default="C")
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "min_grade": self.min_grade,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class RefreshToken(db.Model):
    """Opaque, rotating refresh tokens. Only the hash is stored."""
    __tablename__ = "refresh_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=utcnow)
    user_agent = db.Column(db.String(255))

    @classmethod
    def issue(cls, user, expires_at, user_agent=None):
        raw = secrets.token_urlsafe(48)
        row = cls(user_id=user.id, token_hash=hash_token(raw), expires_at=expires_at,
                  user_agent=(user_agent or "")[:255])
        db.session.add(row)
        return raw, row

    @classmethod
    def lookup(cls, raw):
        if not raw:
            return None
        return cls.query.filter_by(token_hash=hash_token(raw)).first()

    def is_valid(self):
        return not self.revoked and self.expires_at > utcnow()


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)

    @classmethod
    def issue(cls, user, expires_at):
        raw = secrets.token_urlsafe(32)
        row = cls(user_id=user.id, token_hash=hash_token(raw), expires_at=expires_at)
        db.session.add(row)
        return raw, row

    @classmethod
    def lookup(cls, raw):
        if not raw:
            return None
        return cls.query.filter_by(token_hash=hash_token(raw)).first()

    def is_valid(self):
        return self.used_at is None and self.expires_at > utcnow()


class ApiKey(db.Model):
    """Long-lived keys for programmatic scanning. Shown once, stored hashed."""
    __tablename__ = "api_keys"

    PREFIX = "pwp_"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    # First characters of the key so a user can recognise it in the list.
    hint = db.Column(db.String(12), nullable=False)
    key_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False)
    last_used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow)

    @classmethod
    def issue(cls, user, name):
        raw = cls.PREFIX + secrets.token_urlsafe(32)
        row = cls(user_id=user.id, name=name, hint=raw[:10], key_hash=hash_token(raw))
        db.session.add(row)
        return raw, row

    @classmethod
    def lookup(cls, raw):
        if not raw or not raw.startswith(cls.PREFIX):
            return None
        return cls.query.filter_by(key_hash=hash_token(raw)).first()

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "hint": self.hint + "...",
            "revoked": self.revoked,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuditLog(db.Model):
    """Append-only record of who did what. There is no update or delete path."""
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=utcnow, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), index=True)
    actor = db.Column(db.String(255))          # email at the time, survives user deletion
    action = db.Column(db.String(60), nullable=False, index=True)
    resource_type = db.Column(db.String(40))
    resource_id = db.Column(db.Integer)
    detail = db.Column(db.Text)
    ip = db.Column(db.String(64))
    # Non-cascading FK on purpose: audit rows outlive their user.
    __table_args__ = ({"sqlite_autoincrement": True},)

    def to_dict(self):
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "user_id": self.user_id,
            "actor": self.actor,
            "action": self.action,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "detail": self.detail,
            "ip": self.ip,
        }


# ────────────────── AUTHORIZATION DOCUMENTS ──────────────────
# Every non-superadmin user must reference an authorization before running
# scans against a project. The superadmin (app creator) bypasses this entirely.

AUTHORIZATION_STATUSES = ("pending", "approved", "rejected", "expired")


class Authorization(db.Model):
    """Written authorization from a client permitting a pentest engagement."""
    __tablename__ = "authorizations"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    client_name = db.Column(db.String(255), nullable=False)
    client_email = db.Column(db.String(255))
    scope_description = db.Column(db.Text, nullable=False)
    # Allowed targets (one per line, supports *.domain wildcards and CIDR)
    allowed_targets = db.Column(db.Text, nullable=False, default="")
    excluded_targets = db.Column(db.Text, default="")
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    document_filename = db.Column(db.String(255))
    document_hash = db.Column(db.String(64))
    status = db.Column(db.String(20), nullable=False, default="approved")
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utcnow)

    def is_active(self):
        now = utcnow()
        return (self.status == "approved" and
                self.start_date <= now and
                self.end_date >= now)

    def target_in_scope(self, target):
        t = _normalize_target(target)
        allowed = [x.strip().lower() for x in (self.allowed_targets or "").splitlines() if x.strip()]
        excluded = [x.strip().lower() for x in (self.excluded_targets or "").splitlines() if x.strip()]
        # Check exclusions first
        for ex in excluded:
            if ex.startswith("*."):
                if t == ex[2:] or t.endswith(ex[1:]):
                    return False
            elif t == ex:
                return False
        # Check allowed
        if not allowed:
            return True
        for entry in allowed:
            if entry.startswith("*."):
                if t == entry[2:] or t.endswith(entry[1:]):
                    return True
            elif t == entry:
                return True
        return False

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "client_name": self.client_name,
            "client_email": self.client_email,
            "scope_description": self.scope_description,
            "allowed_targets": [t.strip() for t in (self.allowed_targets or "").splitlines() if t.strip()],
            "excluded_targets": [t.strip() for t in (self.excluded_targets or "").splitlines() if t.strip()],
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "document_filename": self.document_filename,
            "status": self.status,
            "is_active": self.is_active(),
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


# ────────────────── FINDINGS (REMEDIATION TRACKING) ──────────────────
FINDING_STATUSES = ("open", "in_progress", "remediated", "accepted_risk", "false_positive", "verified")
FINDING_SEVERITIES = ("critical", "high", "medium", "low", "info")


class Finding(db.Model):
    """Individual vulnerability finding, trackable across scan cycles."""
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=True)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False, default="medium")
    cvss_score = db.Column(db.Float)
    cve_ids = db.Column(db.Text, default="")  # comma-separated
    port = db.Column(db.Integer)
    service = db.Column(db.String(100))
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False, default="open", index=True)
    assigned_to = db.Column(db.String(255))
    status_note = db.Column(db.Text, default="")
    verified_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"))
    created_at = db.Column(db.DateTime, default=utcnow)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "scan_id": self.scan_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cve_ids": [c.strip() for c in (self.cve_ids or "").split(",") if c.strip()],
            "port": self.port,
            "service": self.service,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "status_note": self.status_note,
            "verified_scan_id": self.verified_scan_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ────────────────── ASSET INVENTORY ──────────────────
ASSET_TYPES = ("domain", "subdomain", "ip", "url", "service")


class Asset(db.Model):
    """Persistent attack-surface registry. Auto-populated from recon, tracked over time."""
    __tablename__ = "assets"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    asset_type = db.Column(db.String(20), nullable=False, default="domain")
    value = db.Column(db.String(500), nullable=False)  # the domain, IP, URL
    metadata_json = db.Column(db.Text, default="{}")  # tech stack, ports, etc.
    first_seen = db.Column(db.DateTime, default=utcnow)
    last_seen = db.Column(db.DateTime, default=utcnow)
    status = db.Column(db.String(20), default="active")  # active, removed, monitoring
    notes = db.Column(db.Text, default="")

    __table_args__ = (
        db.UniqueConstraint("project_id", "asset_type", "value", name="uq_asset"),
    )

    def get_metadata(self):
        try:
            return json.loads(self.metadata_json or "{}")
        except (TypeError, ValueError):
            return {}

    def set_metadata(self, data):
        self.metadata_json = json.dumps(data)

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "asset_type": self.asset_type,
            "value": self.value,
            "metadata": self.get_metadata(),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "status": self.status,
            "notes": self.notes,
        }


# ────────────────── RECON RESULTS ──────────────────
class ReconResult(db.Model):
    """Stored recon run output, linked to a project."""
    __tablename__ = "recon_results"

    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("projects.id"), nullable=False, index=True)
    target = db.Column(db.String(500), nullable=False)
    module = db.Column(db.String(40), nullable=False)  # full, subdomains, dns, etc.
    result_json = db.Column(db.Text, nullable=False, default="{}")
    requested_by = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=utcnow, index=True)

    def get_result(self):
        try:
            return json.loads(self.result_json)
        except (TypeError, ValueError):
            return {}

    def to_dict(self):
        return {
            "id": self.id,
            "project_id": self.project_id,
            "target": self.target,
            "module": self.module,
            "result": self.get_result(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
