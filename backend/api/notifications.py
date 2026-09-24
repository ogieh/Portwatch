"""Notifications API: notification-channel CRUD + test send."""

import re

from flask import Blueprint, request, jsonify, g

from models.db import db, NotificationChannel
from core.security import require_auth
import notifier
import audit

bp = Blueprint("notifications", __name__, url_prefix="/api/notifications")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VALID_GRADES = {"A", "B", "C", "D", "F"}


def _owned(channel_id):
    return NotificationChannel.query.filter_by(id=channel_id, user_id=g.user.id).first()


@bp.route("", methods=["GET"])
@require_auth
def list_channels():
    rows = NotificationChannel.query.filter_by(user_id=g.user.id).all()
    return jsonify([c.to_dict() for c in rows])


@bp.route("", methods=["POST"])
@require_auth
def create_channel():
    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "").strip().lower()
    target = (data.get("target") or "").strip()
    min_grade = (data.get("min_grade") or "C").strip().upper()

    if kind not in ("email", "webhook"):
        return jsonify({"error": "kind must be 'email' or 'webhook'"}), 400
    if kind == "email" and not EMAIL_RE.match(target):
        return jsonify({"error": "A valid email address is required"}), 400
    if kind == "webhook" and not target.startswith(("http://", "https://")):
        return jsonify({"error": "Webhook must be a valid http(s) URL"}), 400
    if min_grade not in VALID_GRADES:
        return jsonify({"error": "min_grade must be one of A, B, C, D, F"}), 400

    channel = NotificationChannel(
        user_id=g.user.id, kind=kind, target=target,
        min_grade=min_grade, enabled=True,
    )
    db.session.add(channel)
    db.session.commit()
    audit.record("channel.created", user=g.user, resource=channel, detail=f"{kind}:{target[:120]}")
    return jsonify(channel.to_dict()), 201


@bp.route("/<int:channel_id>", methods=["PATCH"])
@require_auth
def update_channel(channel_id):
    channel = _owned(channel_id)
    if channel is None:
        return jsonify({"error": "Channel not found"}), 404
    data = request.get_json(silent=True) or {}
    if "enabled" in data:
        channel.enabled = bool(data["enabled"])
    if "min_grade" in data:
        mg = (data["min_grade"] or "").strip().upper()
        if mg not in VALID_GRADES:
            return jsonify({"error": "min_grade must be one of A, B, C, D, F"}), 400
        channel.min_grade = mg
    db.session.commit()
    return jsonify(channel.to_dict())


@bp.route("/<int:channel_id>", methods=["DELETE"])
@require_auth
def delete_channel(channel_id):
    channel = _owned(channel_id)
    if channel is None:
        return jsonify({"error": "Channel not found"}), 404
    db.session.delete(channel)
    db.session.commit()
    audit.record("channel.deleted", user=g.user, detail=f"channel #{channel_id}")
    return jsonify({"status": "deleted", "id": channel_id})


@bp.route("/<int:channel_id>/test", methods=["POST"])
@require_auth
def test_channel(channel_id):
    channel = _owned(channel_id)
    if channel is None:
        return jsonify({"error": "Channel not found"}), 404
    ok, detail = notifier.send_test(channel)
    status = 200 if ok else 502
    return jsonify({"ok": ok, "detail": detail}), status
