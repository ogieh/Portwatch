"""
PortWatch Pro application entry point.

Application-factory pattern. `flask --app app run`, `python app.py` and
gunicorn (`gunicorn app:app`) all work. Serves the SPA frontend from
../frontend and the JSON API under /api.
"""

import os
import sys

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS

# The services/, api/, core/, models/ packages are imported by short name from
# within the backend dir, matching how the original project laid out imports.
BACKEND_DIR = os.path.abspath(os.path.dirname(__file__))
for sub in ("core", "api", "services", "models"):
    path = os.path.join(BACKEND_DIR, sub)
    if path not in sys.path:
        sys.path.insert(0, path)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from core.config import Config, validate as validate_config   # noqa: E402
from models.db import db                                       # noqa: E402

FRONTEND_DIR = os.path.abspath(os.path.join(BACKEND_DIR, "..", "frontend"))


def _configure_cors(app):
    """Development: open. Production: only PORTWATCH_CORS_ORIGINS (none = off).
    The SPA is same-origin, so production normally needs no CORS at all."""
    origins = app.config.get("CORS_ORIGINS") or []
    if app.config.get("IS_PRODUCTION"):
        if origins:
            CORS(app, resources={r"/api/*": {"origins": origins}},
                 supports_credentials=False)
    else:
        CORS(app, resources={r"/api/*": {"origins": origins or "*"}})


def _security_headers(response):
    from flask import current_app, request
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=()")
    # Content Security Policy. All scripts are external and same-origin, so
    # script-src stays strict ('self', no inline). Inline styles are used by the
    # SPA's rendered markup, so style-src permits 'unsafe-inline'. Override the
    # whole policy with PORTWATCH_CSP if a deployment needs to.
    default_csp = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )
    csp = current_app.config.get("CSP", default_csp)
    response.headers.setdefault("Content-Security-Policy", csp)
    # HSTS only in production and only over HTTPS, so local HTTP dev is unaffected.
    if current_app.config.get("IS_PRODUCTION") and request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains")
    if response.mimetype == "application/json":
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def create_app(config_object=Config):
    app = Flask(__name__, static_folder=None)
    app.config.from_object(config_object)

    # Cap request bodies to prevent oversized-payload memory pressure. Scan and
    # auth payloads are small; 1 MiB is generous. Override with MAX_CONTENT_LENGTH.
    app.config.setdefault(
        "MAX_CONTENT_LENGTH",
        int(os.environ.get("MAX_CONTENT_LENGTH", str(1 * 1024 * 1024))),
    )

    for warning in validate_config(config_object):
        app.logger.warning("CONFIG: %s", warning)

    _configure_cors(app)
    app.after_request(_security_headers)

    # ---- Request correlation IDs and structured access logging ----
    import time as _time
    import uuid as _uuid
    from flask import g as _g, request as _rq

    @app.before_request
    def _assign_request_id():
        _g._req_id = _rq.headers.get("X-Request-ID") or _uuid.uuid4().hex[:12]
        _g._req_start = _time.perf_counter()

    @app.after_request
    def _access_log(response):
        try:
            dur_ms = (_time.perf_counter() - getattr(_g, "_req_start", _time.perf_counter())) * 1000
            rid = getattr(_g, "_req_id", "-")
            response.headers.setdefault("X-Request-ID", rid)
            # One structured line per request. Avoids logging bodies or query
            # strings (which may carry targets/tokens).
            app.logger.info(
                "access rid=%s method=%s path=%s status=%s dur_ms=%.1f ip=%s",
                rid, _rq.method, _rq.path, response.status_code, dur_ms,
                _rq.headers.get("X-Forwarded-For", _rq.remote_addr or "-"),
            )
        except Exception:  # never let logging break a response
            pass
        return response

    # Consistent JSON error envelopes for the API. Non-API paths fall through to
    # the SPA so the frontend router keeps working.
    def _wants_json():
        from flask import request as _rq
        return _rq.path.startswith("/api") or _rq.accept_mimetypes.best == "application/json"

    from core.validation import ValidationError

    @app.errorhandler(ValidationError)
    def _handle_validation(e):
        return e.response()

    @app.errorhandler(400)
    def _bad_request(e):
        if _wants_json():
            return jsonify({"error": getattr(e, "description", "Bad request")}), 400
        return e

    @app.errorhandler(404)
    def _not_found(e):
        if _wants_json():
            return jsonify({"error": "Not found"}), 404
        return e

    @app.errorhandler(405)
    def _method_not_allowed(e):
        if _wants_json():
            return jsonify({"error": "Method not allowed"}), 405
        return e

    @app.errorhandler(413)
    def _too_large(e):
        return jsonify({"error": "Request body too large"}), 413

    @app.errorhandler(500)
    def _server_error(e):
        app.logger.exception("Unhandled error")
        if _wants_json():
            return jsonify({"error": "Internal server error"}), 500
        return e

    db.init_app(app)

    # Register API blueprints.
    from api.auth import bp as auth_bp
    from api.projects import bp as projects_bp
    from api.scans import bp as scans_bp
    from api.dashboard import bp as dashboard_bp
    from api.schedules import bp as schedules_bp
    from api.notifications import bp as notifications_bp
    from api.audit import bp as audit_bp
    from api.recon import bp as recon_bp
    from api.pentest import bp as pentest_bp

    for bp in (auth_bp, projects_bp, scans_bp, dashboard_bp, schedules_bp,
               notifications_bp, audit_bp, recon_bp, pentest_bp):
        app.register_blueprint(bp)

    # Schema: Alembic brings any database (fresh, or pre-2.1) up to head.
    with app.app_context():
        if app.config.get("AUTO_MIGRATE", True):
            from core.migrate import upgrade_to_head
            upgrade_to_head(app)
        else:
            app.logger.info("AUTO_MIGRATE off; run `alembic upgrade head` yourself.")

    # ---- Meta / health ----
    @app.route("/api/health")
    def health():
        import scanner
        return jsonify({
            "status": "ok",
            "app": app.config["APP_NAME"],
            "version": app.config["APP_VERSION"],
            "env": app.config.get("ENV"),
            "engine": "nmap" if scanner.nmap_available() else "simulated",
            "simulate_forced": bool(app.config.get("SIMULATE_SCANS")),
            "scan_type": app.config.get("NMAP_SCAN_TYPE"),
        })

    @app.route("/api/ready")
    def ready():
        """Readiness probe: confirms the database is reachable. Returns 503 if
        not, so orchestrators do not route traffic to a broken instance."""
        from sqlalchemy import text
        try:
            db.session.execute(text("SELECT 1"))
            return jsonify({"status": "ready"})
        except Exception as exc:  # noqa: BLE001
            app.logger.error("Readiness check failed: %s", exc)
            return jsonify({"status": "not-ready", "reason": "database unavailable"}), 503

    @app.errorhandler(429)
    def _too_many(e):
        return jsonify({"error": "Too many requests"}), 429

    # ---- Serve the SPA frontend ----
    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/<path:path>")
    def static_proxy(path):
        full = os.path.join(FRONTEND_DIR, path)
        if os.path.isfile(full):
            return send_from_directory(FRONTEND_DIR, path)
        # SPA fallback: unknown non-API paths return the app shell.
        return send_from_directory(FRONTEND_DIR, "index.html")

    # ---- Background workers ----
    import scan_jobs
    scan_jobs.start(app)
    import scheduler_service
    scheduler_service.start(app)

    return app


# Module-level app for `python app.py`, `flask --app app run` and gunicorn.
# Tests import create_app and build their own; guard so importing this module
# for that purpose does not also boot a default app against the real DB.
if os.environ.get("PORTWATCH_NO_DEFAULT_APP") != "1":
    app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = not app.config.get("IS_PRODUCTION")
    app.run(debug=debug, host="0.0.0.0", port=port, use_reloader=False)
