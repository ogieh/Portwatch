from flask import Flask, request, jsonify
from flask_cors import CORS

from database import init_db, save_scan, get_history, get_scan_by_id
from scanner import run_scan

app = Flask(__name__)
CORS(app)

init_db()


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "Target is required"}), 400

    try:
        scan_result = run_scan(target)
    except Exception as e:
        # Nmap failures (bad target, nmap not installed, permission issues, etc.)
        return jsonify({"error": f"Scan failed: {str(e)}"}), 500

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


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
