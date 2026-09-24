"""
Request validation helpers for PortWatch Pro API routes.

Small, dependency-free helpers that give every endpoint the same shape of
input handling and error responses, so validation is consistent instead of
re-implemented per route.
"""

from flask import request, jsonify


class ValidationError(Exception):
    """Raised when request input fails validation. Carries an HTTP status."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status

    def response(self):
        return jsonify({"error": self.message}), self.status


def get_json_or_400():
    """Return the parsed JSON body, or raise ValidationError if it is missing
    or malformed. Distinguishes 'no body' from 'body is not valid JSON'."""
    if not request.data:
        return {}
    data = request.get_json(silent=True)
    if data is None:
        raise ValidationError("Request body is not valid JSON.")
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object.")
    return data


def require_fields(data, *fields):
    """Raise ValidationError listing any missing or empty required fields."""
    missing = [f for f in fields if data.get(f) in (None, "", [], {})]
    if missing:
        raise ValidationError(f"Missing required fields: {', '.join(missing)}")
    return True


def clamp_pagination(default_limit=50, max_limit=200):
    """Parse and clamp ?limit and ?offset query params. Returns (limit, offset)."""
    try:
        limit = int(request.args.get("limit", default_limit))
    except (TypeError, ValueError):
        limit = default_limit
    try:
        offset = int(request.args.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    limit = max(1, min(limit, max_limit))
    offset = max(0, offset)
    return limit, offset


def optional_str(data, field, default="", max_len=None):
    """Return a stripped string field with an optional length cap."""
    val = data.get(field, default)
    if not isinstance(val, str):
        raise ValidationError(f"Field '{field}' must be a string.")
    val = val.strip()
    if max_len is not None and len(val) > max_len:
        raise ValidationError(f"Field '{field}' exceeds {max_len} characters.")
    return val
