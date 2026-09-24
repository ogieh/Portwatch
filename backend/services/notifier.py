"""
Notifications for PortWatch Pro.

When a scan completes, any of the project owner's enabled channels whose
severity threshold is met receive an alert. Two channel kinds:

  - webhook : HTTP POST a JSON payload (Slack-compatible 'text' field included).
  - email   : SMTP send, only if SMTP is configured; otherwise logged no-op.

Grade threshold semantics: a channel with min_grade="C" fires when the scan's
grade is C, D or F (i.e. equal to or worse than the threshold).

Every path is wrapped so a notification failure can never abort a scan.
"""

import json
import smtplib
import urllib.request
from email.mime.text import MIMEText

from flask import current_app

_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def _meets_threshold(scan_grade, min_grade):
    if not scan_grade:
        return False
    return _GRADE_RANK.get(scan_grade, 0) >= _GRADE_RANK.get(min_grade, 2)


def _build_message(project, scan):
    full = scan.get_full()
    intel = full.get("intel_summary", {}) or {}
    counts = intel.get("counts", {}) or {}
    lines = [
        f"PortWatch alert: {project.name}",
        f"Target: {scan.target}",
        f"Grade: {scan.risk_grade}  (score {scan.risk_score}/100)",
        f"Profile: {scan.profile}   Trigger: {scan.trigger}",
    ]
    if intel.get("total"):
        lines.append(
            f"Findings: {counts.get('critical',0)} critical, "
            f"{counts.get('high',0)} high, {counts.get('medium',0)} medium"
        )
    if intel.get("unique_cves"):
        lines.append("CVEs: " + ", ".join(intel["unique_cves"][:8]))
    lines.append(scan.summary or "")
    return "\n".join(l for l in lines if l)


def _send_webhook(url, text):
    payload = json.dumps({"text": text, "source": "PortWatch Pro"}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=8)


def _send_email(to_addr, subject, body):
    cfg = current_app.config
    if not cfg.get("SMTP_HOST"):
        current_app.logger.info("SMTP not configured; would email %s: %s", to_addr, subject)
        return
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = cfg["SMTP_FROM"]
    msg["To"] = to_addr
    with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=10) as server:
        server.starttls()
        if cfg.get("SMTP_USER"):
            server.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
        server.sendmail(cfg["SMTP_FROM"], [to_addr], msg.as_string())


def on_scan_complete(project, scan):
    """Dispatch alerts for a finished scan. Best-effort; never raises."""
    owner = project.owner
    if owner is None:
        return

    text = _build_message(project, scan)
    subject = f"[PortWatch] {project.name}: grade {scan.risk_grade} on {scan.target}"

    for ch in owner.channels:
        if not ch.enabled:
            continue
        if not _meets_threshold(scan.risk_grade, ch.min_grade):
            continue
        try:
            if ch.kind == "webhook":
                _send_webhook(ch.target, text)
            elif ch.kind == "email":
                _send_email(ch.target, subject, text)
        except Exception as e:  # pragma: no cover - defensive
            current_app.logger.warning("Channel %s dispatch failed: %s", ch.id, e)


def send_test(channel):
    """Send a test message for a single channel. Returns (ok, detail)."""
    text = "PortWatch Pro test notification. Your channel is configured correctly."
    try:
        if channel.kind == "webhook":
            _send_webhook(channel.target, text)
        elif channel.kind == "email":
            _send_email(channel.target, "PortWatch Pro test notification", text)
        else:
            return False, f"Unknown channel kind '{channel.kind}'"
        return True, "Test dispatched."
    except Exception as e:
        return False, str(e)


def send_password_reset(user, link, minutes):
    """Email a password-reset link. Returns True only if SMTP actually sent it."""
    cfg = current_app.config
    if not cfg.get("SMTP_HOST"):
        current_app.logger.info("SMTP not configured; reset email for %s not sent", user.email)
        return False
    body = (
        f"Hello {user.name},\n\n"
        f"A password reset was requested for your PortWatch Pro account.\n"
        f"Open this link within {minutes} minutes to choose a new password:\n\n"
        f"{link}\n\n"
        f"If you did not request this, you can ignore this email; your password "
        f"will not change.\n"
    )
    try:
        _send_email(user.email, "PortWatch Pro password reset", body)
        return True
    except Exception as e:
        current_app.logger.warning("Reset email to %s failed: %s", user.email, e)
        return False
