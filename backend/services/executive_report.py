"""
Executive summary and enhanced report generation for PortWatch Pro.

Generates:
  1. One-page executive summary (non-technical, board-level)
  2. Full technical report with all findings, remediation, and evidence
  3. Risk matrix and priority actions

Builds on the existing report.py; this module adds the executive layer.
"""

from datetime import datetime
from html import escape


def generate_executive_summary(scan_full, project=None, findings=None, authorization=None):
    """Generate a one-page executive summary as an HTML string."""
    target = scan_full.get("target", "Unknown")
    risk = scan_full.get("risk", {})
    score = risk.get("score", "N/A")
    grade = risk.get("grade", "N/A")
    ports = scan_full.get("ports", [])
    open_ports = [p for p in ports if p.get("state") == "open"]
    high_risk = [p for p in open_ports if p.get("risk") == "high"]
    findings_list = findings or []
    critical_count = len([f for f in findings_list if f.get("severity") == "critical"])
    high_count = len([f for f in findings_list if f.get("severity") == "high"])
    medium_count = len([f for f in findings_list if f.get("severity") == "medium"])
    low_count = len([f for f in findings_list if f.get("severity") == "low"])
    total_findings = critical_count + high_count + medium_count + low_count

    # Overall assessment
    if score == "N/A" or score is None:
        assessment = "Assessment could not be completed."
        risk_level = "Unknown"
    elif score >= 90:
        assessment = "The target demonstrates a strong security posture with no critical exposures identified."
        risk_level = "Low"
    elif score >= 75:
        assessment = "The target has a reasonable security posture with some areas requiring attention."
        risk_level = "Moderate"
    elif score >= 60:
        assessment = "The target has a moderate security posture with several vulnerabilities that should be addressed in the near term."
        risk_level = "Elevated"
    elif score >= 40:
        assessment = "The target has significant security weaknesses that require immediate remediation."
        risk_level = "High"
    else:
        assessment = "The target has critical security deficiencies that pose an immediate risk to the organization."
        risk_level = "Critical"

    # Priority actions
    actions = []
    if critical_count:
        actions.append(f"Remediate {critical_count} critical-severity finding(s) immediately.")
    if high_count:
        actions.append(f"Address {high_count} high-severity finding(s) within 7 days.")
    if high_risk:
        port_list = ", ".join(str(p["port"]) for p in high_risk[:5])
        actions.append(f"Review exposed high-risk services on port(s) {port_list}.")
    if medium_count:
        actions.append(f"Plan remediation for {medium_count} medium-severity finding(s) within 30 days.")
    if not actions:
        actions.append("Maintain current security controls and schedule regular assessments.")

    project_name = project.name if project else "N/A"
    auth_info = ""
    if authorization:
        auth_info = f"""
        <tr><td>Client</td><td>{escape(authorization.get('client_name', 'N/A'))}</td></tr>
        <tr><td>Authorization</td><td>#{authorization.get('id', 'N/A')} (valid {escape(str(authorization.get('start_date', ''))[:10])} to {escape(str(authorization.get('end_date', ''))[:10])})</td></tr>
        """

    grade_color = {"A": "#16A34A", "B": "#65A30D", "C": "#D97706", "D": "#EA580C", "F": "#DC2626"}.get(grade, "#334155")
    ts = scan_full.get("timestamp", "")
    try:
        ts_fmt = datetime.fromisoformat(ts).strftime("%d %B %Y, %H:%M UTC")
    except (TypeError, ValueError):
        ts_fmt = ts or "N/A"

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Executive Summary - {escape(target)}</title>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;max-width:800px;margin:0 auto;padding:40px;color:#1a1a2e;font-size:14px;line-height:1.6}}
h1{{font-size:22px;margin-bottom:4px}}
h2{{font-size:16px;margin-top:28px;margin-bottom:8px;padding-bottom:4px;border-bottom:2px solid #e2e8f0}}
.meta{{color:#64748b;font-size:13px;margin-bottom:24px}}
.score-box{{display:inline-flex;align-items:center;gap:12px;padding:16px 24px;border-radius:12px;background:#f8fafc;border:1px solid #e2e8f0;margin:12px 0}}
.grade{{width:48px;height:48px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-size:22px;font-weight:700}}
.score-num{{font-size:28px;font-weight:700}}
.risk-label{{font-size:13px;font-weight:600;padding:3px 10px;border-radius:4px;color:#fff}}
table{{width:100%;border-collapse:collapse;margin:8px 0}}
td,th{{padding:8px 12px;text-align:left;border-bottom:1px solid #e2e8f0;font-size:13px}}
th{{background:#f8fafc;font-weight:600}}
.actions li{{margin-bottom:6px}}
.sev-bar{{display:flex;gap:8px;margin:4px 0}}
.sev-item{{padding:6px 12px;border-radius:6px;font-size:13px;font-weight:600;color:#fff}}
.footer{{margin-top:40px;padding-top:16px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:11px}}
@media print{{body{{padding:20px}}}}
</style></head><body>
<h1>Executive Summary</h1>
<div class="meta">Penetration Test Report for <strong>{escape(target)}</strong> | {ts_fmt}</div>

<table>
<tr><td style="width:140px;font-weight:600">Project</td><td>{escape(project_name)}</td></tr>
<tr><td>Target</td><td>{escape(target)}</td></tr>
<tr><td>Scan profile</td><td>{escape(scan_full.get('profile', 'standard'))}</td></tr>
<tr><td>Date</td><td>{ts_fmt}</td></tr>
{auth_info}
</table>

<h2>Overall risk assessment</h2>
<div class="score-box">
  <div class="grade" style="background:{grade_color}">{escape(str(grade))}</div>
  <div><div class="score-num">{score}/100</div><div style="font-size:12px;color:#64748b">Security score</div></div>
  <div class="risk-label" style="background:{grade_color}">{risk_level} risk</div>
</div>
<p>{assessment}</p>

<h2>Findings summary</h2>
<div class="sev-bar">
  <div class="sev-item" style="background:#B91C1C">Critical: {critical_count}</div>
  <div class="sev-item" style="background:#DC2626">High: {high_count}</div>
  <div class="sev-item" style="background:#D97706">Medium: {medium_count}</div>
  <div class="sev-item" style="background:#2563EB">Low: {low_count}</div>
</div>
<p>{total_findings} total finding(s) across {len(open_ports)} open service(s).</p>

<h2>Priority actions</h2>
<ol class="actions">
{''.join(f'<li>{escape(a)}</li>' for a in actions)}
</ol>

<h2>Scope</h2>
<table>
<tr><td style="width:140px">Open ports</td><td>{len(open_ports)}</td></tr>
<tr><td>High-risk services</td><td>{len(high_risk)}</td></tr>
<tr><td>Engine</td><td>{escape(scan_full.get('engine', 'unknown'))}</td></tr>
</table>

<div class="footer">
Generated by PortWatch Pro | This document is confidential and intended for the named client only.
</div>
</body></html>"""
