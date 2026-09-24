"""
Background scan runner for PortWatch Pro.

A deep nmap scan can take minutes. Running it inside the HTTP request ties up
a server worker and can time out in the browser, so every scan is executed
here instead: the API creates a queued Scan row, submit() hands its id to a
small thread pool, and the frontend polls GET /api/scans/<id> until the
status leaves queued/running.

Per scan the runner provides:

  - a cancel flag (cancel()) polled by the engine between phases;
  - a hard ceiling per profile (SCAN_MAX_SECONDS): the engine runs in an inner
    thread; if it overruns, the scan is marked failed (timed out), the cancel
    flag is set so the engine stops at its next boundary, and the late result
    is discarded.

The pool lives in this process. With one gunicorn worker (the documented
deployment) that is exactly one queue. If you move to several worker
processes, replace submit() with a queue such as RQ or Celery; the API
surface (submit/cancel/status) stays the same.
"""

import threading
from concurrent.futures import ThreadPoolExecutor

_executor = None
_app = None
_jobs = {}            # scan_id -> {"cancel": Event, "started": float}
_lock = threading.Lock()


def start(app):
    """Bind the runner to an app. Idempotent."""
    global _executor, _app
    _app = app
    if _executor is None:
        workers = max(1, int(app.config.get("SCAN_WORKERS", 2)))
        _executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan")
    return _executor


def shutdown(wait=False):
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=wait, cancel_futures=True)
        _executor = None


def submit(scan_id):
    """Queue a scan for execution. In inline mode (tests) it runs right now."""
    if _app is None:
        raise RuntimeError("scan_jobs.start(app) has not been called")
    if _app.config.get("SCAN_JOBS_INLINE"):
        return _run(scan_id)
    cancel = threading.Event()
    with _lock:
        _jobs[scan_id] = {"cancel": cancel}
    return _executor.submit(_run, scan_id)


def cancel(scan_id):
    """Flip the cancel flag for a running job. Returns True if it was tracked."""
    with _lock:
        job = _jobs.get(scan_id)
    if job is None:
        return False
    job["cancel"].set()
    return True


def is_tracked(scan_id):
    with _lock:
        return scan_id in _jobs


def _run(scan_id):
    import scan_service

    with _lock:
        job = _jobs.setdefault(scan_id, {"cancel": threading.Event()})
    cancel_event = job["cancel"]

    with _app.app_context():
        from models.db import db, Scan
        row = db.session.get(Scan, scan_id)
        if row is None:
            _forget(scan_id)
            return None
        profile = row.profile
        ceiling = (_app.config.get("SCAN_MAX_SECONDS") or {}).get(profile)
        db.session.remove()

    result = {}

    def target():
        with _app.app_context():
            try:
                result["row_id"] = scan_id
                scan_service.execute_scan(scan_id, cancel_check=cancel_event.is_set)
            except Exception as e:  # pragma: no cover - defensive
                _app.logger.exception("Scan %s crashed: %s", scan_id, e)
            finally:
                from models.db import db
                db.session.remove()

    if _app.config.get("SCAN_JOBS_INLINE") or not ceiling:
        target()
        _forget(scan_id)
        return scan_id

    worker = threading.Thread(target=target, name=f"scan-{scan_id}", daemon=True)
    worker.start()
    worker.join(timeout=ceiling)
    if worker.is_alive():
        cancel_event.set()
        with _app.app_context():
            from models.db import db
            scan_service.mark_timed_out(scan_id, ceiling)
            db.session.remove()
        _app.logger.warning("Scan %s exceeded %ss and was marked failed", scan_id, ceiling)
    _forget(scan_id)
    return scan_id


def _forget(scan_id):
    with _lock:
        _jobs.pop(scan_id, None)
