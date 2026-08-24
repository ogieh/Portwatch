from flask import Flask, request, jsonify
from flask_cors import CORS

from database import init_db, save_scan, get_history, get_scan_by_id
from scanner import run_scan, SCAN_PROFILES, DEFAULT_PROFILE
from scoring import compute_risk
from compliance import generate_compliance_tags
from diffing import build_diff
from report import build_report_html

app = Flask(__name__)
CORS(app)

init_db()


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()
    profile = data.get("profile") or DEFAULT_PROFILE

    if not target:
        return jsonify({"error": "Target is required"}), 400

    if profile not in SCAN_PROFILES:
        return jsonify({
            "error": f"Unknown scan profile '{profile}'. Valid profiles: "
                     f"{', '.join(sorted(SCAN_PROFILES))}"
        }), 400

    try:
        scan_result = run_scan(target, profile)
    except Exception as e:
        # Nmap failures (bad target, nmap not installed, permission issues, etc.)
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

    # Scored and tagged at save time so history never silently re-grades
    # itself if the formula changes later.
    scan_result["risk"] = compute_risk(scan_result["ports"])
    scan_result["compliance"] = generate_compliance_tags(scan_result["ports"])

    saved = save_scan(scan_result)
    return jsonify(saved)


@app.route("/api/history", methods=["GET"])
def history():
    return jsonify(get_history())


@app.route("/api/history/<int:scan_id>", methods=["GET"])
def history_item(scan_id):
    record = get_scan_by_id(scan_id)
    if record is None:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(record)


@app.route("/api/history/<int:before_id>/diff/<int:after_id>", methods=["GET"])
def history_diff(before_id, after_id):
    before = get_scan_by_id(before_id)
    after = get_scan_by_id(after_id)
    if before is None or after is None:
        return jsonify({"error": "One or both scans were not found"}), 404

    try:
        diff = build_diff(before, after)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if diff["profile_mismatch"]:
        diff["warning"] = (
            f"Profile mismatch: #{before_id} used '{diff['before']['profile']}' and "
            f"#{after_id} used '{diff['after']['profile']}'. Port and score "
            f"differences may just reflect the deeper scan, not a real change."
        )
    return jsonify(diff)


@app.route("/api/report/<int:scan_id>", methods=["GET"])
def report(scan_id):
    record = get_scan_by_id(scan_id)
    if record is None:
        return jsonify({"error": "Scan not found"}), 404
    return build_report_html(record)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
