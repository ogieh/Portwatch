"""
Recon API: subdomain enumeration, DNS, WHOIS, tech detection, email
security, directory brute, WAF detection, traceroute, exploit lookup.

All endpoints require authentication. Simulation mode is inherited from
the scanner config (PORTWATCH_SIMULATE or nmap unavailability).
"""

from flask import Blueprint, request, jsonify, g, current_app

from core.security import require_auth
from core.ratelimit import rate_limit
import recon
import exploit_db
import audit

bp = Blueprint("recon", __name__, url_prefix="/api/recon")


def _use_sim():
    return bool(current_app.config.get("SIMULATE_SCANS")) or recon.SIMULATE


@bp.route("/full", methods=["POST"])
@require_auth
@rate_limit("RATELIMIT_SCAN", name="recon-full")
def full_recon():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    audit.record("recon.full", user=g.user, detail=target)
    result = recon.run_full_recon(target, simulate=_use_sim())
    return jsonify(result)


@bp.route("/subdomains", methods=["POST"])
@require_auth
def subdomains():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(recon.enumerate_subdomains(target, simulate=_use_sim()))


@bp.route("/dns", methods=["POST"])
@require_auth
def dns():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(recon.dns_lookup(target, simulate=_use_sim()))


@bp.route("/whois", methods=["POST"])
@require_auth
def whois():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(recon.whois_lookup(target, simulate=_use_sim()))


@bp.route("/technologies", methods=["POST"])
@require_auth
def technologies():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(recon.detect_technologies(target, simulate=_use_sim()))


@bp.route("/email-security", methods=["POST"])
@require_auth
def email_security():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(recon.check_email_security(target, simulate=_use_sim()))


@bp.route("/directories", methods=["POST"])
@require_auth
def directories():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(recon.directory_bruteforce(target, simulate=_use_sim()))


@bp.route("/waf", methods=["POST"])
@require_auth
def waf():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(recon.detect_waf(target, simulate=_use_sim()))


@bp.route("/traceroute", methods=["POST"])
@require_auth
def traceroute():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    return jsonify(recon.traceroute(target, simulate=_use_sim()))


@bp.route("/exploits", methods=["POST"])
@require_auth
def exploits():
    """Look up exploits for a completed scan's findings."""
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    if not scan_id:
        # Direct version lookup
        version = (data.get("version") or "").strip()
        if not version:
            return jsonify({"error": "scan_id or version is required"}), 400
        results = exploit_db.search_exploits(version, simulate=_use_sim())
        return jsonify({"version": version, "exploits": results})

    from models.db import Scan, Project
    scan = (
        Scan.query.join(Project)
        .filter(Scan.id == scan_id, Project.user_id == g.user.id)
        .first()
    )
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan.status != "completed":
        return jsonify({"error": "Scan must be completed"}), 400

    result = exploit_db.scan_exploit_lookup(scan.get_full(), simulate=_use_sim())
    return jsonify(result)
