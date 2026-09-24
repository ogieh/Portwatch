"""
Central configuration for PortWatch Pro.

Everything tunable lives here and can be overridden with environment variables,
so the same code runs on a laptop, in Docker, or in CI without edits.

Two environments are recognised through PORTWATCH_ENV:

  development (default)  relaxed defaults: dev secret allowed, CORS open,
                         reset tokens echoed to the log, auto schema creation.
  production             refuses to start with the built-in secret, CORS
                         restricted to PORTWATCH_CORS_ORIGINS, reset tokens
                         only ever leave via email.
"""

import os
from datetime import datetime, timezone


def utcnow():
    """Timezone-aware UTC 'now' as a naive datetime (DB columns are naive).

    Replaces the deprecated datetime.utcnow() while keeping stored values naive
    so comparisons against existing naive columns stay valid.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

DEV_SECRET = "dev-secret-change-me-in-production"


def _bool(env_value, default=False):
    if env_value is None:
        return default
    return env_value.strip().lower() in ("1", "true", "yes", "on")


def _int(env_value, default):
    try:
        return int(env_value) if env_value not in (None, "") else default
    except ValueError:
        return default


def _list(env_value):
    if not env_value:
        return []
    return [x.strip() for x in env_value.split(",") if x.strip()]


class Config:
    # ---- Environment ----
    ENV = (os.environ.get("PORTWATCH_ENV") or "development").strip().lower()
    IS_PRODUCTION = ENV == "production"

    # ---- Core ----
    SECRET_KEY = os.environ.get("PORTWATCH_SECRET", DEV_SECRET)
    # Access tokens are short-lived; refresh tokens keep the session alive.
    JWT_EXPIRY_HOURS = _int(os.environ.get("PORTWATCH_JWT_HOURS"), 1)
    REFRESH_EXPIRY_DAYS = _int(os.environ.get("PORTWATCH_REFRESH_DAYS"), 30)
    PASSWORD_RESET_MINUTES = _int(os.environ.get("PORTWATCH_RESET_MINUTES"), 30)
    # Base URL used in password-reset emails (where the SPA lives).
    PUBLIC_URL = (os.environ.get("PORTWATCH_PUBLIC_URL") or "http://localhost:5000").rstrip("/")

    # ---- Database ----
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("PORTWATCH_DB_URI") or f"sqlite:///{os.path.join(DATA_DIR, 'portwatch.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    # Bring the schema up to date on boot (Alembic). Turn off if you run
    # `alembic upgrade head` as a separate deploy step.
    AUTO_MIGRATE = _bool(os.environ.get("PORTWATCH_AUTO_MIGRATE"), default=True)

    # ---- CORS ----
    # The SPA is served from the same origin, so CORS is only needed when the
    # API is called from elsewhere. Development: open. Production: listed only.
    CORS_ORIGINS = _list(os.environ.get("PORTWATCH_CORS_ORIGINS"))

    # ---- Rate limiting (per client IP, single-process in-memory) ----
    RATELIMIT_ENABLED = _bool(os.environ.get("PORTWATCH_RATELIMIT"), default=True)
    RATELIMIT_LOGIN = os.environ.get("PORTWATCH_RATELIMIT_LOGIN", "10/minute")
    RATELIMIT_REGISTER = os.environ.get("PORTWATCH_RATELIMIT_REGISTER", "5/minute")
    RATELIMIT_RESET = os.environ.get("PORTWATCH_RATELIMIT_RESET", "5/minute")
    RATELIMIT_SCAN = os.environ.get("PORTWATCH_RATELIMIT_SCAN", "10/minute")

    # ---- Scanning ----
    # When nmap is missing OR this flag is on, the scanner produces realistic
    # synthetic results so the whole product is demonstrable anywhere.
    SIMULATE_SCANS = _bool(os.environ.get("PORTWATCH_SIMULATE"), default=False)
    # connect (-sT, no privileges needed) or syn (-sS, needs root / NET_RAW).
    NMAP_SCAN_TYPE = (os.environ.get("PORTWATCH_NMAP_SCAN_TYPE") or "connect").strip().lower()
    # Background scan workers. Manual and scheduled scans share this pool.
    SCAN_WORKERS = _int(os.environ.get("PORTWATCH_SCAN_WORKERS"), 2)
    # Run scans inline in the request (tests / debugging only).
    SCAN_JOBS_INLINE = _bool(os.environ.get("PORTWATCH_SCAN_INLINE"), default=False)
    # Hard ceiling per profile, seconds. A scan past its ceiling is marked
    # failed (timed out) and its result discarded.
    SCAN_MAX_SECONDS = {
        "quick": _int(os.environ.get("PORTWATCH_MAX_QUICK"), 180),
        "standard": _int(os.environ.get("PORTWATCH_MAX_STANDARD"), 600),
        "deep": _int(os.environ.get("PORTWATCH_MAX_DEEP"), 1800),
    }

    # ---- Scheduler ----
    SCHEDULER_ENABLED = _bool(os.environ.get("PORTWATCH_SCHEDULER"), default=True)
    SCHEDULER_POLL_SECONDS = _int(os.environ.get("PORTWATCH_SCHEDULER_POLL"), 30)

    # ---- Notifications ----
    # Optional SMTP for email alerts. If unset, email channels degrade to a
    # logged no-op (webhooks still work), so the feature never crashes a scan.
    SMTP_HOST = os.environ.get("PORTWATCH_SMTP_HOST")
    SMTP_PORT = _int(os.environ.get("PORTWATCH_SMTP_PORT"), 587)
    SMTP_USER = os.environ.get("PORTWATCH_SMTP_USER")
    SMTP_PASSWORD = os.environ.get("PORTWATCH_SMTP_PASSWORD")
    SMTP_FROM = os.environ.get("PORTWATCH_SMTP_FROM", "portwatch@localhost")

    # ---- App metadata (surfaced in reports / UI) ----
    APP_NAME = "PortWatch Pro"
    APP_VERSION = "2.2.0"


def validate(config):
    """Refuse unsafe production settings. Returns a list of warnings for dev."""
    warnings = []
    is_prod = getattr(config, "IS_PRODUCTION", False)
    secret = getattr(config, "SECRET_KEY", DEV_SECRET)
    if secret == DEV_SECRET or len(secret) < 16:
        msg = ("PORTWATCH_SECRET is the built-in development value or too short. "
               "Set PORTWATCH_SECRET to a long random string.")
        if is_prod:
            raise RuntimeError("Refusing to start in production: " + msg)
        warnings.append(msg)
    if is_prod and getattr(config, "SQLALCHEMY_DATABASE_URI", "").startswith("sqlite"):
        warnings.append("Production is using SQLite. PostgreSQL is recommended for "
                        "concurrent use (see docs/DEPLOYMENT.md).")
    if getattr(config, "NMAP_SCAN_TYPE", "connect") not in ("connect", "syn"):
        raise RuntimeError("PORTWATCH_NMAP_SCAN_TYPE must be 'connect' or 'syn'.")
    return warnings
