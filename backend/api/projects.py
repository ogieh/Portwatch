"""Projects API: CRUD, scoped to the authenticated user."""

from flask import Blueprint, request, jsonify, g

from models.db import db, Project
from core.security import require_auth
import audit

bp = Blueprint("projects", __name__, url_prefix="/api/projects")


def _owned_or_404(project_id):
    project = Project.query.filter_by(id=project_id, user_id=g.user.id).first()
    return project


@bp.route("", methods=["GET"])
@require_auth
def list_projects():
    projects = (
        Project.query.filter_by(user_id=g.user.id)
        .order_by(Project.created_at.desc())
        .all()
    )
    return jsonify([p.to_dict(with_stats=True) for p in projects])


@bp.route("", methods=["POST"])
@require_auth
def create_project():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Project name is required"}), 400

    allowed, err = _parse_allowlist(data.get("allowed_targets"))
    if err:
        return jsonify({"error": err}), 400

    project = Project(
        user_id=g.user.id,
        name=name,
        description=(data.get("description") or "").strip(),
        allowed_targets=allowed,
    )
    db.session.add(project)
    db.session.commit()
    audit.record("project.created", user=g.user, resource=project, detail=name)
    return jsonify(project.to_dict(with_stats=True)), 201


def _parse_allowlist(value):
    """Accepts a list or newline/comma separated string. Returns (text, error)."""
    if value is None:
        return "", None
    if isinstance(value, str):
        parts = [p for chunk in value.splitlines() for p in chunk.split(",")]
    elif isinstance(value, (list, tuple)):
        parts = [str(p) for p in value]
    else:
        return None, "allowed_targets must be a list or a newline-separated string"
    cleaned = []
    for p in parts:
        p = p.strip().lower()
        if not p:
            continue
        if len(p) > 255 or any(c.isspace() for c in p):
            return None, f"Invalid allowed target '{p[:40]}'"
        cleaned.append(p)
    if len(cleaned) > 500:
        return None, "At most 500 allowed targets per project"
    return "\n".join(dict.fromkeys(cleaned)), None


@bp.route("/<int:project_id>", methods=["GET"])
@require_auth
def get_project(project_id):
    project = _owned_or_404(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404
    data = project.to_dict(with_stats=True)
    data["scans"] = [s.to_summary() for s in project.scans]
    return jsonify(data)


@bp.route("/<int:project_id>", methods=["PATCH"])
@require_auth
def update_project(project_id):
    project = _owned_or_404(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404
    data = request.get_json(silent=True) or {}
    if "name" in data:
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "Project name cannot be empty"}), 400
        project.name = name
    if "description" in data:
        project.description = (data.get("description") or "").strip()
    if "allowed_targets" in data:
        allowed, err = _parse_allowlist(data.get("allowed_targets"))
        if err:
            return jsonify({"error": err}), 400
        project.allowed_targets = allowed
    db.session.commit()
    audit.record("project.updated", user=g.user, resource=project, detail=project.name)
    return jsonify(project.to_dict(with_stats=True))


@bp.route("/<int:project_id>", methods=["DELETE"])
@require_auth
def delete_project(project_id):
    project = _owned_or_404(project_id)
    if project is None:
        return jsonify({"error": "Project not found"}), 404
    name, count = project.name, len(project.scans)
    db.session.delete(project)
    db.session.commit()
    audit.record("project.deleted", user=g.user, detail=f"project #{project_id} {name} ({count} scans)")
    return jsonify({"status": "deleted", "id": project_id})
