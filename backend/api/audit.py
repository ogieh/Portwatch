"""Audit API: read-only view of the append-only audit log.

Analysts see their own events; admins see everything.
"""

from flask import Blueprint, request, jsonify, g

from core.security import require_auth
import audit as audit_service

bp = Blueprint("audit", __name__, url_prefix="/api/audit")


@bp.route("", methods=["GET"])
@require_auth
def list_events():
    limit = request.args.get("limit", 100, type=int)
    action = (request.args.get("action") or "").strip() or None
    rows = audit_service.query_for(g.user, limit=limit, action=action)
    return jsonify([r.to_dict() for r in rows])
