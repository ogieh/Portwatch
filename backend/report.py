"""
Client-facing report generation for PortWatch.

Builds a standalone, print-styled HTML report from a stored scan record.
Served at GET /api/report/<id>; the browser's "Save as PDF" turns it into
a client-ready document with zero extra server dependencies.

Deliberately light-themed: this page is meant for paper/PDF, unlike the
dark operator UI.
"""

from datetime import datetime
from html import escape

RISK_ORDER = {"high": 0, "medium": 1, "low": 2}


def _esc(value):
    return escape(str(value if value is not None else "—"))


def _fmt_ts(ts):
    try:
        return datetime.fromisoformat(ts).strftime("%d %b %Y, %H:%M UTC")
    except (TypeError, ValueError):
        return ts or ""


def _grade_color(letter):
    return {
        "A": "#16A34A", "B": "#65A30D", "C": "#D97706",
        "D": "#EA580C", "F": "#DC2626",
    }.get(letter, "#334155")


_VERDICT_LABEL = {
    "none_observed": ("No rate limiting observed", "#DC2626"),
    "throttled": ("Throttling in place", "#15803D"),
    "lockout": ("Lockout protection", "#15803D"),
    "captcha": ("CAPTCHA protection", "#15803D"),
}


def _credential_checks_section(record):
    cc = record.get("credential_checks")
    if cc is None:
        return """
        <section>
          <h2>Credential &amp; Lockout Checks</h2>
          <p class="empty">Not performed for this scan.</p>
        </section>"""

    rows = []
    for f in cc.get("http_login_findings") or []:
        label, color = _VERDICT_LABEL.get(f.get("verdict"), (f.get("verdict"), "#334155"))
        rows.append(
            f"<tr><td>{_esc(f.get('url'))}</td>"
            f"<td><span class='risk' style='background:{color}1a;color:{color};'>{_esc(label)}</span></td>"
            f"<td>{_esc(f.get('detail'))}</td></tr>"
        )
    for d in cc.get("db_findings") or []:
        color = "#DC2626" if d.get("vulnerable") else "#15803D"
        label = "Vulnerable" if d.get("vulnerable") else "No issue found"
        rows.append(
            f"<tr><td>Port {_esc(d.get('port'))}</td>"
            f"<td><span class='risk' style='background:{color}1a;color:{color};'>{_esc(label)}</span></td>"
            f"<td>{_esc(d.get('check'))}: {_esc(d.get('detail'))}</td></tr>"
        )

    if not rows:
        body = ("<p class='empty'>Checks were enabled but no login endpoints or "
                "credential-protected services were found to test.</p>")
    else:
        note = ""
        if any(r.get("verdict") == "none_observed" for r in cc.get("http_login_findings") or []):
            note = ("<p class='meta' style='margin-top:8px;'>Verdicts reflect a small number of "
                    "controlled failed attempts; they indicate observed behaviour, not a guarantee "
                    "about sustained attack scenarios.</p>")
        body = f"""
        <table>
          <thead><tr><th>Endpoint</th><th>Verdict</th><th>Detail</th></tr></thead>
          <tbody>{''.join(rows)}</tbody>
        </table>{note}"""
    if cc.get("error"):
        body += f"<p class='empty'>Partial failure: {_esc(cc['error'])}</p>"

    return f"""
    <section>
      <h2>Credential &amp; Lockout Checks</h2>
      {body}
    </section>"""


def build_report_html(record):
    risk = record.get("risk") or {}
    score = risk.get("score")
    grade = risk.get("grade")
    compliance = record.get("compliance") or []
    open_ports = [
        p for p in record.get("ports", [])
        if p.get("state") == "open"
    ]
    open_ports.sort(key=lambda p: (RISK_ORDER.get(p.get("risk"), 3), p.get("port", 0)))

    grade_block = ""
    if score is not None and grade:
        color = _grade_color(grade)
        grade_block = f"""
        <div class="grade-box" style="border-color:{color};">
          <div class="grade-letter" style="color:{color};">{_esc(grade)}</div>
          <div class="grade-score">{_esc(score)}/100</div>
        </div>"""

    compliance_html = ""
    if compliance:
        items = "".join(
            f"""
            <li>
              <strong>{_esc(t['category'])} — {_esc(t['name'])}</strong>
              <ul>{''.join(f'<li>{_esc(e)}</li>' for e in t['evidence'])}</ul>
            </li>"""
            for t in compliance
        )
        compliance_html = f"""
        <section>
          <h2>Framework Mapping — OWASP Top 10 (2021)</h2>
          <ul class="compliance">{items}</ul>
        </section>"""

    credential_html = _credential_checks_section(record)

    port_rows = ""
    if open_ports:
        port_rows = "".join(
            f"""
            <tr>
              <td class="mono">{_esc(p['port'])}</td>
              <td><span class="risk risk-{_esc(p['risk'])}">{_esc(p['risk'])}</span></td>
              <td>{_esc(p['service'])}</td>
              <td>{_esc(p['version'])}</td>
            </tr>"""
            for p in open_ports
        )
    else:
        port_rows = '<tr><td colspan="4" class="empty">No open ports detected in the scanned range.</td></tr>'

    breakdown_html = ""
    breakdown = risk.get("breakdown") or []
    if breakdown:
        rows = "".join(
            f"<tr><td>{_esc(b['reason'])}</td><td class='mono neg'>{_esc(b['points'])}</td></tr>"
            for b in breakdown
        )
        breakdown_html = f"""
        <section>
          <h2>How This Score Was Calculated</h2>
          <table>
            <thead><tr><th>Finding</th><th>Points</th></tr></thead>
            <tbody>{rows}
            <tr class="total"><td>Final score</td><td class="mono">{_esc(score)}</td></tr></tbody>
          </table>
        </section>"""

    profile = record.get("profile") or "standard"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>PortWatch Report — {_esc(record.get('target'))}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #F1F5F9; color: #0F172A; line-height: 1.6;
    padding: 32px 16px;
  }}
  .page {{ max-width: 800px; margin: 0 auto; background: #FFFFFF;
           border: 1px solid #E2E8F0; border-radius: 8px; padding: 40px 48px; }}
  header {{ display: flex; justify-content: space-between; align-items: flex-start;
            border-bottom: 3px solid #0F172A; padding-bottom: 18px; margin-bottom: 28px; gap: 24px; flex-wrap: wrap; }}
  .brand {{ font-family: Consolas, monospace; font-weight: 700; font-size: 20px; letter-spacing: -0.02em; }}
  .brand span {{ color: #0284C7; }}
  .brand small {{ display: block; font-size: 11px; color: #64748B; letter-spacing: 0.12em;
                  text-transform: uppercase; font-weight: 500; margin-top: 2px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  .meta {{ color: #64748B; font-size: 13px; }}
  .grade-box {{ border: 2px solid; border-radius: 8px; padding: 10px 22px; text-align: center; }}
  .grade-letter {{ font-size: 40px; font-weight: 800; line-height: 1.1; }}
  .grade-score {{ font-size: 12px; color: #64748B; }}
  h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: 0.1em;
        color: #475569; margin: 28px 0 10px; }}
  section:first-of-type h2 {{ margin-top: 0; }}
  .summary {{ background: #F8FAFC; border-left: 3px solid #0284C7;
              padding: 14px 18px; font-size: 14px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; background: #F1F5F9; padding: 8px 12px;
        font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #475569; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #E2E8F0; vertical-align: top; }}
  tr.total td {{ font-weight: 700; border-top: 2px solid #0F172A; border-bottom: none; }}
  .neg {{ color: #DC2626; }}
  .empty {{ color: #64748B; font-style: italic; }}
  .mono {{ font-family: Consolas, monospace; }}
  .risk {{ display: inline-block; padding: 1px 8px; border-radius: 99px;
           font-size: 11px; font-weight: 700; text-transform: uppercase; }}
  .risk-high {{ background: #FEE2E2; color: #B91C1C; }}
  .risk-medium {{ background: #FEF3C7; color: #B45309; }}
  .risk-low {{ background: #DCFCE7; color: #15803D; }}
  ul.compliance {{ list-style: none; }}
  ul.compliance > li {{ margin-bottom: 14px; font-size: 14px; }}
  ul.compliance ul {{ margin: 6px 0 0 20px; font-size: 13px; color: #334155; }}
  ul.compliance li {{ margin-bottom: 3px; }}
  footer {{ margin-top: 36px; padding-top: 16px; border-top: 1px solid #E2E8F0;
            font-size: 11px; color: #94A3B8; line-height: 1.7; }}
  .toolbar {{ max-width: 800px; margin: 0 auto 16px; text-align: right; }}
  .toolbar button {{ background: #0284C7; color: #fff; border: none; border-radius: 6px;
                     padding: 9px 20px; font-size: 14px; font-weight: 600; cursor: pointer; }}
  .toolbar button:hover {{ background: #0369A1; }}
  @media print {{
    body {{ background: #FFFFFF; padding: 0; }}
    .page {{ border: none; border-radius: 0; padding: 0; max-width: none; }}
    .toolbar {{ display: none; }}
  }}
</style>
</head>
<body>
  <div class="toolbar"><button onclick="window.print()">Print / Save as PDF</button></div>
  <div class="page">
    <header>
      <div>
        <div class="brand">Port<span>Watch</span><small>surface scanner · assessment report</small></div>
        <h1 style="margin-top:14px;">Attack Surface Report — {_esc(record.get('target'))}</h1>
        <p class="meta">
          Scanned {_esc(_fmt_ts(record.get('timestamp')))}
          &nbsp;·&nbsp; Profile: {_esc(profile.title())}
          &nbsp;·&nbsp; Scan #{_esc(record.get('id', '?'))}
        </p>
      </div>
      {grade_block}
    </header>

    <section>
      <h2>Executive Summary</h2>
      <p class="summary">{_esc(record.get('summary'))}</p>
    </section>

    {compliance_html}

    {credential_html}

    <section>
      <h2>Open Ports &amp; Services</h2>
      <table>
        <thead><tr><th>Port</th><th>Risk</th><th>Service</th><th>Version</th></tr></thead>
        <tbody>{port_rows}</tbody>
      </table>
    </section>

    {breakdown_html}

    <footer>
      Generated by PortWatch. This report reflects a point-in-time scan of the
      stated target within the scope authorised by its owner. Only scan systems
      you own or have explicit written permission to test.
    </footer>
  </div>
</body>
</html>"""
