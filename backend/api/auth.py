"""Auth API: register, login, refresh, logout, password change/reset, API keys."""

import re
from datetime import timedelta

from flask import Blueprint, request, jsonify, g, current_app

from config import utcnow
from models.db import db, User, PasswordResetToken, ApiKey
from core.security import (
    require_auth, require_session, issue_session, rotate_refresh, revoke_refresh,
)
from core.ratelimit import rate_limit
import audit
import notifier

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD = 8
MAX_API_KEYS = 10


def _password_problem(password):
    if len(password or "") < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters"
    if len(password) > 128:
        return "Password is too long"
    return None


# ------------------------------------------------------------ register/login

@bp.route("/register", methods=["POST"])
@rate_limit("RATELIMIT_REGISTER", name="register")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    name = (data.get("name") or "").strip()
    password = data.get("password") or ""

    if not EMAIL_RE.match(email):
        return jsonify({"error": "A valid email address is required"}), 400
    if not name:
        return jsonify({"error": "Name is required"}), 400
    problem = _password_problem(password)
    if problem:
        return jsonify({"error": problem}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "An account with that email already exists"}), 409

    # First-ever user becomes admin; keeps single-tenant demos simple.
    role = "admin" if User.query.count() == 0 else "analyst"
    user = User(email=email, name=name, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    audit.record("auth.register", user=user, resource=user, detail=f"role={role}")

    return jsonify(issue_session(user)), 201


@bp.route("/login", methods=["POST"])
@rate_limit("RATELIMIT_LOGIN", name="login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if user is None or not user.check_password(password):
        audit.record("auth.login_failed", detail=f"email={email[:120]}")
        return jsonify({"error": "Invalid email or password"}), 401

    audit.record("auth.login", user=user, resource=user)
    return jsonify(issue_session(user))


@bp.route("/me", methods=["GET"])
@require_auth
def me():
    return jsonify({"user": g.user.to_dict(), "auth": g.auth_kind})


# ------------------------------------------------------------ token lifecycle

@bp.route("/refresh", methods=["POST"])
def refresh():
    data = request.get_json(silent=True) or {}
    session, err = rotate_refresh(data.get("refresh_token"))
    if err:
        return jsonify({"error": err}), 401
    db.session.commit()
    audit.record("auth.refresh", user=db.session.get(User, session["user"]["id"]))
    return jsonify(session)


@bp.route("/logout", methods=["POST"])
def logout():
    """Revoke the presented refresh token. The short-lived access token simply
    expires; call /logout-all to invalidate it immediately."""
    data = request.get_json(silent=True) or {}
    revoked = revoke_refresh(data.get("refresh_token"))
    audit.record("auth.logout", detail="refresh token revoked" if revoked else "no token")
    return jsonify({"status": "ok"})


@bp.route("/logout-all", methods=["POST"])
@require_session
def logout_all():
    """Sign out every device: bumps token_version so all access tokens fail."""
    g.user.revoke_all_sessions()
    db.session.commit()
    audit.record("auth.logout_all", user=g.user, resource=g.user)
    return jsonify({"status": "ok"})


# ------------------------------------------------------------ passwords

@bp.route("/password", methods=["POST"])
@require_session
def change_password():
    data = request.get_json(silent=True) or {}
    current = data.get("current_password") or ""
    new = data.get("new_password") or ""
    if not g.user.check_password(current):
        audit.record("auth.password_change_failed", user=g.user, resource=g.user)
        return jsonify({"error": "Current password is incorrect"}), 401
    problem = _password_problem(new)
    if problem:
        return jsonify({"error": problem}), 400
    if current == new:
        return jsonify({"error": "New password must differ from the current one"}), 400

    g.user.set_password(new)
    g.user.revoke_all_sessions()
    db.session.commit()
    audit.record("auth.password_changed", user=g.user, resource=g.user)
    # Hand back a fresh session so the current device stays signed in.
    return jsonify(issue_session(g.user))


@bp.route("/forgot", methods=["POST"])
@rate_limit("RATELIMIT_RESET", name="forgot")
def forgot_password():
    """Always answers 200 so it cannot be used to enumerate accounts."""
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    response = {"status": "ok",
                "message": "If that address has an account, a reset link has been sent."}
    user = User.query.filter_by(email=email).first() if email else None
    if user is None:
        audit.record("auth.reset_requested", detail=f"unknown email={email[:120]}")
        return jsonify(response)

    minutes = current_app.config.get("PASSWORD_RESET_MINUTES", 30)
    raw, _ = PasswordResetToken.issue(user, expires_at=utcnow() + timedelta(minutes=minutes))
    db.session.commit()
    audit.record("auth.reset_requested", user=user, resource=user)

    link = f"{current_app.config['PUBLIC_URL']}/#reset/{raw}"
    delivered = notifier.send_password_reset(user, link, minutes)
    if not delivered and not current_app.config.get("IS_PRODUCTION"):
        # No SMTP in development: surface the token so the flow is testable.
        current_app.logger.info("Password reset link for %s: %s", user.email, link)
        response["dev_reset_token"] = raw
    return jsonify(response)


@bp.route("/reset", methods=["POST"])
@rate_limit("RATELIMIT_RESET", name="reset")
def reset_password():
    data = request.get_json(silent=True) or {}
    raw = (data.get("token") or "").strip()
    new = data.get("password") or ""
    row = PasswordResetToken.lookup(raw)
    if row is None or not row.is_valid() or row.user is None:
        return jsonify({"error": "Reset link is invalid or has expired"}), 400
    problem = _password_problem(new)
    if problem:
        return jsonify({"error": problem}), 400

    user = row.user
    user.set_password(new)
    user.revoke_all_sessions()
    row.used_at = utcnow()
    db.session.commit()
    audit.record("auth.reset_completed", user=user, resource=user)
    return jsonify(issue_session(user))


# ------------------------------------------------------------ API keys

@bp.route("/api-keys", methods=["GET"])
@require_session
def list_api_keys():
    rows = ApiKey.query.filter_by(user_id=g.user.id).order_by(ApiKey.id.desc()).all()
    return jsonify([k.to_dict() for k in rows])


@bp.route("/api-keys", methods=["POST"])
@require_session
def create_api_key():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()[:80]
    if not name:
        return jsonify({"error": "Give the key a name so you can recognise it later"}), 400
    active = ApiKey.query.filter_by(user_id=g.user.id, revoked=False).count()
    if active >= MAX_API_KEYS:
        return jsonify({"error": f"At most {MAX_API_KEYS} active API keys per account"}), 400
    raw, row = ApiKey.issue(g.user, name)
    db.session.commit()
    audit.record("apikey.created", user=g.user, resource=row, detail=name)
    body = row.to_dict()
    body["key"] = raw  # shown exactly once
    return jsonify(body), 201


@bp.route("/api-keys/<int:key_id>", methods=["DELETE"])
@require_session
def revoke_api_key(key_id):
    row = ApiKey.query.filter_by(id=key_id, user_id=g.user.id).first()
    if row is None:
        return jsonify({"error": "API key not found"}), 404
    row.revoked = True
    db.session.commit()
    audit.record("apikey.revoked", user=g.user, resource=row, detail=row.name)
    return jsonify({"status": "revoked", "id": key_id})
