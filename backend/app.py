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
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    if response.mimetype == "application/json":
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def create_app(config_object=Config):
    app = Flask(__name__, static_folder=None)
    app.config.from_object(config_object)

    for warning in validate_config(config_object):
        app.logger.warning("CONFIG: %s", warning)

    _configure_cors(app)
    app.after_request(_security_headers)

    db.init_app(app)

    # Register API blueprints.
    from api.auth import bp as auth_bp
    from api.projects import bp as projects_bp
    from api.scans import bp as scans_bp
    from api.dashboard import bp as dashboard_bp
    from api.schedules import bp as schedules_bp
    from api.notifications import bp as notifications_bp
    from api.audit import bp as audit_bp

    for bp in (auth_bp, projects_bp, scans_bp, dashboard_bp, schedules_bp,
               notifications_bp, audit_bp):
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
