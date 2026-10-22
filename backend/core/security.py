"""
Authentication for PortWatch Pro.

Three credentials are accepted on the Authorization header:

  Bearer <access JWT>   short-lived (JWT_EXPIRY_HOURS, default 1h). Carries the
                        user's token_version so a password change or
                        "sign out everywhere" invalidates it at once.
  Bearer pwp_...        an API key (long-lived, revocable, stored hashed).
  X-API-Key: pwp_...    same API key on its own header.

Refresh tokens are opaque random strings stored hashed (models.RefreshToken)
and rotated on every use. A single @require_auth decorator loads the current
user onto flask.g so every protected route can read g.user without re-parsing.
"""

import functools
from datetime import datetime, timedelta, timezone

import jwt
from flask import request, jsonify, g, current_app

from core.config import utcnow
from models.db import db, User, RefreshToken, ApiKey


# ---------------------------------------------------------------- access JWT

def create_token(user):
    """Short-lived access token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "role": user.role,
        "ver": user.token_version or 0,
        "typ": "access",
        "iat": now,
        "exp": now + timedelta(hours=current_app.config["JWT_EXPIRY_HOURS"]),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def decode_token(token):
    return jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])


# ------------------------------------------------------------ refresh tokens

def issue_session(user):
    """Access token + new refresh token. Returns the JSON-ready dict."""
    days = current_app.config.get("REFRESH_EXPIRY_DAYS", 30)
    raw_refresh, _ = RefreshToken.issue(
        user, expires_at=utcnow() + timedelta(days=days),
        user_agent=request.headers.get("User-Agent") if request else None,
    )
    db.session.commit()
    return {
        "token": create_token(user),
        "refresh_token": raw_refresh,
        "expires_in": current_app.config["JWT_EXPIRY_HOURS"] * 3600,
        "user": user.to_dict(),
    }


def rotate_refresh(raw_refresh):
    """Validate a refresh token, revoke it, and issue a fresh pair.
    Returns (session_dict, None) or (None, error_message)."""
    row = RefreshToken.lookup(raw_refresh)
    if row is None or not row.is_valid():
        return None, "Refresh token is invalid or expired"
    user = row.user
    if user is None:
        return None, "Account no longer exists"
    row.revoked = True
    return issue_session(user), None


def revoke_refresh(raw_refresh):
    row = RefreshToken.lookup(raw_refresh)
    if row is not None:
        row.revoked = True
        db.session.commit()
        return True
    return False


# ------------------------------------------------------------------ helpers

def _extract_bearer():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return None


def _extract_api_key():
    key = request.headers.get("X-API-Key")
    if key:
        return key.strip()
    bearer = _extract_bearer()
    if bearer and bearer.startswith(ApiKey.PREFIX):
        return bearer
    return None


def _authenticate():
    """Returns (user, auth_kind, error_response_or_None)."""
    api_key = _extract_api_key()
    if api_key:
        row = ApiKey.lookup(api_key)
        if row is None or row.revoked or row.user is None:
            return None, None, (jsonify({"error": "Invalid or revoked API key"}), 401)
        row.last_used_at = utcnow()
        db.session.commit()
        return row.user, "api_key", None

    token = _extract_bearer()
    if not token:
        return None, None, (jsonify({"error": "Authentication required"}), 401)
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        return None, None, (jsonify({"error": "Session expired, please log in again",
                                     "code": "token_expired"}), 401)
    except jwt.InvalidTokenError:
        return None, None, (jsonify({"error": "Invalid authentication token"}), 401)

    if payload.get("typ", "access") != "access":
        return None, None, (jsonify({"error": "Invalid authentication token"}), 401)

    user = db.session.get(User, int(payload["sub"]))
    if user is None:
        return None, None, (jsonify({"error": "Account no longer exists"}), 401)
    if int(payload.get("ver", 0)) != int(user.token_version or 0):
        return None, None, (jsonify({"error": "Session was signed out, please log in again",
                                     "code": "token_revoked"}), 401)
    return user, "jwt", None


def require_auth(fn):
    """Protect a route. On success, flask.g.user is the authenticated User and
    flask.g.auth_kind is 'jwt' or 'api_key'."""

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        user, kind, err = _authenticate()
        if err is not None:
            return err
        g.user = user
        g.auth_kind = kind
        return fn(*args, **kwargs)

    return wrapper


def require_admin(fn):
    @functools.wraps(fn)
    @require_auth
    def wrapper(*args, **kwargs):
        if g.user.role != "admin":
            return jsonify({"error": "Administrator access required"}), 403
        return fn(*args, **kwargs)

    return wrapper


def require_session(fn):
    """Like require_auth but rejects API keys (for account-management routes)."""

    @functools.wraps(fn)
    @require_auth
    def wrapper(*args, **kwargs):
        if g.auth_kind != "jwt":
            return jsonify({"error": "This action requires an interactive session, not an API key"}), 403
        return fn(*args, **kwargs)

    return wrapper


def client_ip():
    """Best-effort client address, honouring a single trusted proxy hop."""
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return (request.remote_addr or "")[:64]
