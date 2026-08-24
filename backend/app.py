import re
import threading
import time
import uuid

from flask import Flask, request, jsonify
from flask_cors import CORS

from database import init_db, save_scan, get_history, get_scan_by_id
from scanner import run_scan

app = Flask(__name__)
CORS(app)

init_db()

# In-memory job store. Fine for a single-instance dev/portfolio tool --
# not meant to survive a server restart or run across multiple workers.
_jobs = {}
_jobs_lock = threading.Lock()

# How long a finished job's result stays cached after completion, so a
# dropped network response (flaky wifi, backgrounded tab) can be retried
# by the client instead of permanently losing an already-completed scan.
JOB_RETENTION_SECONDS = 300

STAGE_LABELS = {
    "queued": "Queued",
    "resolving": "Resolving target",
    "port_scan": "Scanning ports",
    "service_scripts": "Running service/vulnerability scripts",
    "finalizing": "Building report",
    "done": "Done",
    "error": "Error",
}

# Rough weight of each stage, used only to render a progress percentage.
# This is an estimate, not a measurement -- real scan time varies. It's
# shown as "roughly this far along," not a precise countdown.
STAGE_PROGRESS = {
    "queued": 2,
    "resolving": 8,
    "port_scan": 20,
    "service_scripts": 60,
    "finalizing": 95,
    "done": 100,
    "error": 100,
}


def _sanitize_target(raw):
    """Strip a pasted URL down to a bare hostname/IP nmap can actually use.
    Handles http(s):// prefixes, trailing slashes/paths, and stray whitespace.
    Returns '' if nothing usable is left."""
    target = raw.strip()
    target = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", target)  # strip any scheme
    target = target.split("/")[0]   # drop any path
    target = target.split("?")[0]   # drop any query string
    target = target.split("#")[0]   # drop any fragment
    target = target.strip().rstrip(".")
    return target


def _sweep_stale_jobs():
    """Remove finished jobs past their retention window. Called opportunistically
    on each new scan request rather than running a separate background timer."""
    now = time.time()
    stale = [
        jid for jid, j in _jobs.items()
        if j["status"] in ("done", "error") and (now - j.get("finished_at", now)) > JOB_RETENTION_SECONDS
    ]
    for jid in stale:
        del _jobs[jid]


def _run_job(job_id, target):
    def on_progress(stage):
        with _jobs_lock:
            if job_id in _jobs:
                _jobs[job_id]["stage"] = stage

    try:
        result = run_scan(target, on_progress=on_progress)
        with _jobs_lock:
            _jobs[job_id]["status"] = "done"
            _jobs[job_id]["stage"] = "done"
            _jobs[job_id]["result"] = result
            _jobs[job_id]["finished_at"] = time.time()
    except Exception as e:
        with _jobs_lock:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["stage"] = "error"
            _jobs[job_id]["error"] = str(e)
            _jobs[job_id]["finished_at"] = time.time()


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    raw_target = data.get("target", "")
    target = _sanitize_target(raw_target)

    if not target:
        return jsonify({"error": "Enter a valid target hostname or IP address."}), 400

    job_id = str(uuid.uuid4())
    with _jobs_lock:
        _sweep_stale_jobs()
        _jobs[job_id] = {
            "status": "running",
            "stage": "queued",
            "start_time": time.time(),
            "finished_at": None,
            "target": target,
            "result": None,
            "error": None,
            "saved": False,
        }

    thread = threading.Thread(target=_run_job, args=(job_id, target), daemon=True)
    thread.start()

    return jsonify({"job_id": job_id, "target": target}), 202


@app.route("/api/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            return jsonify({"error": "Unknown or expired job id"}), 404

        response = {
            "status": job["status"],  # "running" | "done" | "error"
            "stage": job["stage"],
            "stage_label": STAGE_LABELS.get(job["stage"], job["stage"]),
            "progress_pct": STAGE_PROGRESS.get(job["stage"], 0),
            # Computed live on every poll, not just at stage transitions,
            # so the counter doesn't visibly freeze during a long stage.
            "elapsed": round(time.time() - job["start_time"], 1),
        }

        if job["status"] == "done":
            # Save exactly once even if the client polls this multiple times
            # (e.g. retrying after a dropped response) -- avoids duplicate
            # history rows for a single scan.
            if not job["saved"]:
                saved = save_scan(job["result"])
                job["result"] = saved
                job["saved"] = True
            response["result"] = job["result"]
            # Kept around (not deleted) until JOB_RETENTION_SECONDS elapses,
            # so a retried poll after a dropped response still gets the result.
        elif job["status"] == "error":
            response["error"] = job["error"]

    return jsonify(response)


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


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
