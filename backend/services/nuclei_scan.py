"""
Nuclei vulnerability scanning for PortWatch.

Opt-in external-tool scanner (like Nikto/wpscan in web_vuln.py): runs nuclei
against discovered web services and normalizes findings. Missing nuclei is
never an error; simulation fallback is seeded and deterministic.
"""

import hashlib
import json
import random
import shutil
import subprocess
from urllib.parse import urlparse

from core.config import Config

SEVERITIES = ["info", "low", "medium", "high", "critical"]
_HTTPS_PORTS = {443, 8443, 9443}


def _seeded_rng(target):
    seed = int(hashlib.sha256(str(target).encode()).hexdigest(), 16) % (2**32)
    return random.Random(seed)


def nuclei_available():
    if (getattr(Config, "NUCLEI_ENABLED", "auto") or "auto").lower() == "off":
        return False
    return shutil.which("nuclei") is not None


def _first(value):
    if isinstance(value, list):
        return value[0] if value else ""
    return value or ""


def _split_host_port(matched, fallback_host=""):
    host, port = fallback_host, 0
    try:
        p = urlparse(matched if "://" in matched else f"//{matched}")
        host = p.hostname or fallback_host
        port = p.port or (443 if p.scheme == "https" else 80 if p.scheme == "http" else 0)
    except Exception:
        pass
    return host, port


def _normalize(obj):
    info = obj.get("info") or {}
    if not isinstance(info, dict):
        info = {}
    matched = obj.get("matched-at") or obj.get("matched_at") or obj.get("url") or ""
    host, port = _split_host_port(matched, obj.get("host") or "")
    if obj.get("port"):
        try:
            port = int(obj["port"])
        except (TypeError, ValueError):
            pass
    ref = info.get("reference") or ""
    if isinstance(ref, list):
        ref = ", ".join(str(r) for r in ref)
    cvss = (info.get("classification") or {}).get("cvss-score") if isinstance(info.get("classification"), dict) else None
    return {
        "template_id": obj.get("template-id") or obj.get("template_id") or "",
        "name": info.get("name") or "",
        "severity": str(info.get("severity") or "info").lower(),
        "matched_at": matched,
        "host": host,
        "port": port,
        "description": info.get("description") or "",
        "reference": ref,
        "cvss": cvss,
    }


def parse_jsonl(text):
    """Parse nuclei -jsonl output; skip malformed lines."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            out.append(_normalize(obj))
    return out


def simulate_nuclei(target, open_web_ports):
    rng = _seeded_rng(target)
    pool = [
        ("apache-cve-2021-41773", "Apache 2.4.49 Path Traversal", "critical", "CVE-2021-41773", 9.8),
        ("exposed-env-file", "Exposed .env File", "high", "", None),
        ("phpinfo-detect", "phpinfo() Exposure", "medium", "", None),
        ("missing-x-frame-options", "Missing X-Frame-Options", "low", "", None),
    ]
    findings = []
    for port in sorted(open_web_ports or []):
        scheme = "https" if port in _HTTPS_PORTS else "http"
        tid, name, sev, ref, cvss = pool[0] if port in (80, 443) else rng.choice(pool)
        findings.append({
            "template_id": tid, "name": name, "severity": sev,
            "matched_at": f"{scheme}://{target}:{port}/",
            "host": target, "port": port,
            "description": f"Simulated finding: {name}",
            "reference": ref, "cvss": cvss,
        })
        if rng.random() < 0.5:
            tid, name, sev, ref, cvss = rng.choice(pool[1:])
            findings.append({
                "template_id": tid, "name": name, "severity": sev,
                "matched_at": f"{scheme}://{target}:{port}/",
                "host": target, "port": port,
                "description": f"Simulated finding: {name}",
                "reference": ref, "cvss": cvss,
            })
    return findings


def _severity_floor(min_severity):
    s = (min_severity or "low").lower()
    if s not in SEVERITIES:
        s = "low"
    return ",".join(SEVERITIES[SEVERITIES.index(s):])

_REQUEST_TIMEOUT = 10  # seconds, nuclei per-request; `timeout` is the subprocess ceiling


def run_nuclei(target, open_web_ports, min_severity="low", tags="", timeout=300,
               cancel_check=None, simulate=False):
    if simulate:
        return {"enabled": True, "findings": simulate_nuclei(target, open_web_ports), "engine": "simulated"}
    noop = {"enabled": False, "findings": [], "engine": "nuclei"}
    if not nuclei_available() or not open_web_ports:
        return noop
    try:
        cmd = ["nuclei", "-jsonl", "-silent", "-severity", _severity_floor(min_severity),
               "-timeout", str(_REQUEST_TIMEOUT)]
        if tags:
            cmd += ["-tags", tags]
        for port in open_web_ports:
            scheme = "https" if int(port) in _HTTPS_PORTS else "http"
            cmd += ["-u", f"{scheme}://{target}:{int(port)}"]
        if cancel_check and cancel_check():
            return noop
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=int(timeout))
        return {"enabled": True, "findings": parse_jsonl(r.stdout), "engine": "nuclei"}
    except Exception:
        return noop
